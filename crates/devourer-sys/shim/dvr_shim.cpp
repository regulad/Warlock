// SPDX-License-Identifier: GPL-2.0-only
//
// Implementation of the dvr_shim C ABI over devourer. See dvr_shim.h for the
// threading contract.

#include "dvr_shim.h"

#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <string>

#include <libusb.h>

#include "DeviceConfig.h"
#include "IRadio.h"
#include "RxPacket.h"
#include "SelectedChannel.h"
#include "UsbDeviceLock.h"
#include "UsbOpen.h"
#include "WiFiDriver.h"
#include "logger.h"

struct dvr_radio {
  Logger_t logger;
  libusb_context *ctx = nullptr;
  libusb_device_handle *handle = nullptr;
  int iface = 0;
  std::shared_ptr<devourer::UsbDeviceLock> lock;
  std::unique_ptr<IRadio> dev;
  // Serialises TX and control calls. devourer's send_packet takes no lock of
  // its own and may retune; the RX callback never takes this mutex.
  std::mutex ctl_mu;
};

namespace {

thread_local std::string g_last_error;

int fail(int code, std::string msg) {
  g_last_error = std::move(msg);
  return code;
}

// Runs `fn` with every C++ exception turned into DVR_E_EXCEPTION.
template <typename F> int guarded(const char *what, F &&fn) {
  try {
    return fn();
  } catch (const std::exception &e) {
    return fail(DVR_E_EXCEPTION, std::string(what) + ": " + e.what());
  } catch (...) {
    return fail(DVR_E_EXCEPTION, std::string(what) + ": unknown exception");
  }
}

Logger::Level to_level(uint8_t level) {
  switch (level) {
  case DVR_LOG_TRACE: return Logger::Level::Trace;
  case DVR_LOG_DEBUG: return Logger::Level::Debug;
  case DVR_LOG_INFO: return Logger::Level::Info;
  case DVR_LOG_WARN: return Logger::Level::Warn;
  case DVR_LOG_ERROR: return Logger::Level::Error;
  default: return Logger::Level::Silent;
  }
}

SelectedChannel make_channel(uint8_t channel, uint8_t width, uint8_t offset) {
  SelectedChannel ch{};
  ch.Channel = channel;
  ch.ChannelOffset = offset;
  ch.ChannelWidth = static_cast<ChannelWidth_t>(width);
  return ch;
}

// Releases whatever dvr_open managed to acquire, in devourer's mandated
// order: device, then interface, then handle, then context, then lock.
void teardown(dvr_radio *r) {
  if (r->dev) {
    try {
      r->dev->StopRxLoop();
      // The responder keeps ACKing after Stop() and even after the process
      // exits, so disarm it explicitly.
      r->dev->ClearAckResponder();
      r->dev->Stop();
    } catch (...) {
    }
    r->dev.reset();
  }
  if (r->handle != nullptr) {
    libusb_release_interface(r->handle, r->iface);
    libusb_close(r->handle);
    r->handle = nullptr;
  }
  if (r->ctx != nullptr) {
    libusb_exit(r->ctx);
    r->ctx = nullptr;
  }
  r->lock.reset();
}

} // namespace

extern "C" {

const char *dvr_last_error(void) { return g_last_error.c_str(); }

int dvr_open(uint16_t vid, uint16_t pid, const dvr_config *cfg,
             dvr_radio **out) {
  if (cfg == nullptr || out == nullptr)
    return fail(DVR_E_ARG, "dvr_open: null argument");
  *out = nullptr;

  auto r = std::make_unique<dvr_radio>();
  const int rc = guarded("dvr_open", [&]() -> int {
    r->logger = std::make_shared<Logger>();
    r->logger->set_level(to_level(cfg->log_level));
    r->logger->set_diag_stream(stderr);
    if (cfg->hop_prof != 0)
      r->logger->events().configure(stderr);
    else
      r->logger->events().disable();

    int urc = libusb_init(&r->ctx);
    if (urc < 0) {
      r->ctx = nullptr;
      return fail(DVR_E_USB,
                  std::string("libusb_init: ") + libusb_error_name(urc));
    }
    libusb_set_option(r->ctx, LIBUSB_OPTION_LOG_LEVEL,
                      LIBUSB_LOG_LEVEL_WARNING);

    r->handle = libusb_open_device_with_vid_pid(r->ctx, vid, pid);
    if (r->handle == nullptr) {
      char msg[160];
      std::snprintf(msg, sizeof msg,
                    "no openable USB device %04x:%04x (is WinUSB bound to it?)",
                    vid, pid);
      return fail(DVR_E_NOT_FOUND, msg);
    }

    urc = devourer::claim_interface_reset_reopen(r->ctx, r->handle, r->logger,
                                                 cfg->usb_reset != 0, r->lock);
    if (urc != 0) {
      return fail(urc == LIBUSB_ERROR_BUSY ? DVR_E_BUSY : DVR_E_USB,
                  std::string("claim/reset: ") + libusb_error_name(urc));
    }
    r->iface = devourer::find_wifi_interface(r->handle);
    if (r->iface < 0)
      r->iface = 0;

    devourer::DeviceConfig dcfg{};
    dcfg.tx.retry_limit = cfg->retry_limit;
    dcfg.tuning.fastretune_fw = cfg->fastretune_fw;
    dcfg.tuning.thermal_track = cfg->thermal_track != 0;
    dcfg.debug.hop_prof = cfg->hop_prof != 0;
    dcfg.rx.rx_mode =
        cfg->rx_spsc != 0 ? devourer::RxMode::SpscFat : devourer::RxMode::Async;

    WiFiDriver driver(r->logger);
    r->dev = driver.CreateRadio(r->handle, r->ctx, r->lock, dcfg);
    if (!r->dev)
      return fail(DVR_E_UNSUPPORTED,
                  "devourer has no backend for this chip in this build");
    return DVR_OK;
  });

  if (rc != DVR_OK) {
    teardown(r.get());
    return rc;
  }
  *out = r.release();
  return DVR_OK;
}

int dvr_init(dvr_radio *r, uint8_t channel, uint8_t width, uint8_t offset) {
  if (r == nullptr || !r->dev)
    return fail(DVR_E_ARG, "dvr_init: no radio");
  return guarded("InitWrite", [&]() -> int {
    std::lock_guard<std::mutex> g(r->ctl_mu);
    r->dev->InitWrite(make_channel(channel, width, offset));
    return DVR_OK;
  });
}

int dvr_run_rx(dvr_radio *r, dvr_rx_cb cb, void *user) {
  if (r == nullptr || !r->dev || cb == nullptr)
    return fail(DVR_E_ARG, "dvr_run_rx: null argument");
  return guarded("StartRxLoop", [&]() -> int {
    r->dev->StartRxLoop([cb, user](const Packet &p) {
      if (p.RxAtrib.pkt_rpt_type != RX_PACKET_TYPE::NORMAL_RX)
        return;
      size_t len = p.Data.size();
      if (p.RxAtrib.fcs_present && len >= 4)
        len -= 4;
      dvr_rx_frame f{};
      f.data = p.Data.data();
      f.len = len;
      f.tsfl = p.RxAtrib.tsfl;
      f.data_rate = p.RxAtrib.data_rate;
      f.rssi[0] = p.RxAtrib.rssi[0];
      f.rssi[1] = p.RxAtrib.rssi[1];
      f.bw = p.RxAtrib.bw;
      f.crc_err = p.RxAtrib.crc_err ? 1 : 0;
      cb(user, &f);
    });
    return DVR_OK;
  });
}

void dvr_stop_rx(dvr_radio *r) {
  if (r != nullptr && r->dev)
    r->dev->StopRxLoop();
}

int dvr_send(dvr_radio *r, const uint8_t *buf, size_t len) {
  if (r == nullptr || !r->dev || buf == nullptr || len == 0)
    return fail(DVR_E_ARG, "dvr_send: null argument");
  return guarded("send_packet", [&]() -> int {
    std::lock_guard<std::mutex> g(r->ctl_mu);
    return r->dev->send_packet(buf, len)
               ? DVR_OK
               : fail(DVR_E_FAILED, "send_packet returned false");
  });
}

int dvr_fast_retune(dvr_radio *r, uint8_t channel) {
  if (r == nullptr || !r->dev)
    return fail(DVR_E_ARG, "dvr_fast_retune: no radio");
  return guarded("FastRetune", [&]() -> int {
    std::lock_guard<std::mutex> g(r->ctl_mu);
    r->dev->FastRetune(channel, true);
    return DVR_OK;
  });
}

int dvr_set_channel(dvr_radio *r, uint8_t channel, uint8_t width,
                    uint8_t offset) {
  if (r == nullptr || !r->dev)
    return fail(DVR_E_ARG, "dvr_set_channel: no radio");
  return guarded("SetMonitorChannel", [&]() -> int {
    std::lock_guard<std::mutex> g(r->ctl_mu);
    r->dev->SetMonitorChannel(make_channel(channel, width, offset));
    return DVR_OK;
  });
}

int dvr_reapply_txpower(dvr_radio *r) {
  if (r == nullptr || !r->dev)
    return fail(DVR_E_ARG, "dvr_reapply_txpower: no radio");
  return guarded("ReApplyTxPower", [&]() -> int {
    std::lock_guard<std::mutex> g(r->ctl_mu);
    return r->dev->ReApplyTxPower()
               ? DVR_OK
               : fail(DVR_E_FAILED, "ReApplyTxPower returned false");
  });
}

int dvr_set_ack_responder(dvr_radio *r, const uint8_t mac[6]) {
  if (r == nullptr || !r->dev || mac == nullptr)
    return fail(DVR_E_ARG, "dvr_set_ack_responder: null argument");
  return guarded("SetAckResponder", [&]() -> int {
    devourer::MacAddr m;
    std::memcpy(m.bytes.data(), mac, 6);
    std::lock_guard<std::mutex> g(r->ctl_mu);
    return r->dev->SetAckResponder(m)
               ? DVR_OK
               : fail(DVR_E_FAILED, "SetAckResponder refused (multicast MAC "
                                    "or station identity armed?)");
  });
}

void dvr_clear_ack_responder(dvr_radio *r) {
  if (r == nullptr || !r->dev)
    return;
  try {
    std::lock_guard<std::mutex> g(r->ctl_mu);
    r->dev->ClearAckResponder();
  } catch (...) {
  }
}

int dvr_read_tsf(dvr_radio *r, uint64_t *out) {
  if (r == nullptr || !r->dev || out == nullptr)
    return fail(DVR_E_ARG, "dvr_read_tsf: null argument");
  return guarded("ReadTsf", [&]() -> int {
    std::lock_guard<std::mutex> g(r->ctl_mu);
    *out = r->dev->ReadTsf();
    return DVR_OK;
  });
}

void dvr_close(dvr_radio *r) {
  if (r == nullptr)
    return;
  teardown(r);
  delete r;
}

} // extern "C"
