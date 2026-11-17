/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * dvr_shim: a narrow C ABI over the devourer userspace Realtek Wi-Fi driver,
 * for Warlock's Rust code. devourer is C++20 and throws; nothing here throws,
 * and every devourer call is caught at this boundary.
 *
 * Threading contract (inherited from devourer, see its src/UsbDeviceLock.cpp
 * and src/IRadio.h):
 *  - dvr_open and dvr_close must run on the same thread. On Windows the
 *    per-adapter lock is a named mutex, which is owned by the thread that
 *    took it.
 *  - dvr_run_rx blocks; run it on its own thread. Every other call may come
 *    from any thread. The shim serialises TX and control calls with one
 *    mutex, which the RX callback never takes.
 *  - Stop the RX loop (dvr_stop_rx) and join its thread before dvr_close.
 *  - The RX callback must not block for long and must not call back into the
 *    shim for TX or control.
 */
#ifndef WARLOCK_DVR_SHIM_H
#define WARLOCK_DVR_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dvr_radio dvr_radio;

enum {
  DVR_OK = 0,
  DVR_E_ARG = -1,
  DVR_E_USB = -2,         /* libusb failure; see dvr_last_error() */
  DVR_E_NOT_FOUND = -3,   /* no device with that VID:PID (or not WinUSB-bound) */
  DVR_E_BUSY = -4,        /* another process owns the adapter */
  DVR_E_UNSUPPORTED = -5, /* chip not compiled into this devourer build */
  DVR_E_FAILED = -6,      /* devourer reported failure (returned false) */
  DVR_E_EXCEPTION = -7,   /* devourer threw; see dvr_last_error() */
};

/* Mirrors devourer's ChannelWidth_t for the widths Warlock uses. */
enum {
  DVR_WIDTH_20 = 0,
  DVR_WIDTH_40 = 1,
  DVR_WIDTH_80 = 2,
};

/* Mirrors devourer's Logger::Level. */
enum {
  DVR_LOG_TRACE = 0,
  DVR_LOG_DEBUG = 1,
  DVR_LOG_INFO = 2,
  DVR_LOG_WARN = 3,
  DVR_LOG_ERROR = 4,
  DVR_LOG_SILENT = 5,
};

typedef struct dvr_config {
  /* Hardware retransmissions for unicast frames (DeviceConfig::Tx::retry_limit;
   * devourer's default 0 sends each unicast frame exactly once). */
  int32_t retry_limit;
  /* DeviceConfig::Tuning::fastretune_fw: 0 software hop, 1 firmware
   * intra-band hop, 2 firmware hop including cross-band. */
  int32_t fastretune_fw;
  /* DeviceConfig::Tuning::thermal_track (devourer default on). */
  uint8_t thermal_track;
  /* Nonzero: RxMode::SpscFat (callback on a dedicated consumer thread).
   * Zero: RxMode::Async (callback on the thread inside dvr_run_rx). */
  uint8_t rx_spsc;
  /* Nonzero: libusb_reset_device before claiming (devourer's recommended
   * cold start). */
  uint8_t usb_reset;
  /* DVR_LOG_*; devourer's diagnostics go to stderr, its JSON events are off. */
  uint8_t log_level;
} dvr_config;

typedef struct dvr_rx_frame {
  /* The 802.11 MPDU with the FCS already stripped. Valid only for the
   * duration of the callback. */
  const uint8_t *data;
  size_t len;
  /* Low 32 bits of the MAC's TSF (microseconds) when the frame was received. */
  uint32_t tsfl;
  /* Realtek hardware rate code (devourer RxAtrib.data_rate). */
  uint16_t data_rate;
  /* Raw per-path RX power for paths A and B; dBm = value - 110. */
  uint8_t rssi[2];
  /* 0/1/2 = 20/40/80 MHz. */
  uint8_t bw;
  uint8_t crc_err;
} dvr_rx_frame;

typedef void (*dvr_rx_cb)(void *user, const dvr_rx_frame *frame);

/* Thread-local description of the last failure on the calling thread. */
const char *dvr_last_error(void);

/* Open, claim (and optionally reset) the adapter, and construct the radio.
 * Does not bring the chip up; call dvr_init next. */
int dvr_open(uint16_t vid, uint16_t pid, const dvr_config *cfg,
             dvr_radio **out);

/* Chip bring-up on the given channel (devourer IRadio::InitWrite). */
int dvr_init(dvr_radio *r, uint8_t channel, uint8_t width, uint8_t offset);

/* Blocking RX loop (devourer IRadio::StartRxLoop). Returns after
 * dvr_stop_rx. Only normal received frames reach `cb`; firmware reports are
 * filtered out. */
int dvr_run_rx(dvr_radio *r, dvr_rx_cb cb, void *user);
void dvr_stop_rx(dvr_radio *r);

/* Inject one frame: a radiotap header followed by the 802.11 MPDU, no FCS.
 * Include a RATE (or MCS/VHT) radiotap field; without one devourer falls back
 * to 1 Mbps CCK, which is invalid at 5 GHz. */
int dvr_send(dvr_radio *r, const uint8_t *buf, size_t len);

/* Lean same-width hop (IRadio::FastRetune); see dvr_config.fastretune_fw. */
int dvr_fast_retune(dvr_radio *r, uint8_t channel);
/* Full retune (IRadio::SetMonitorChannel). */
int dvr_set_channel(dvr_radio *r, uint8_t channel, uint8_t width,
                    uint8_t offset);
/* Re-apply the TX power table, e.g. after a cross-band hop. */
int dvr_reapply_txpower(dvr_radio *r);

/* Arm the hardware ACK/BlockAck responder for a unicast MAC address. */
int dvr_set_ack_responder(dvr_radio *r, const uint8_t mac[6]);
void dvr_clear_ack_responder(dvr_radio *r);

/* Read the 64-bit MAC TSF (microseconds). */
int dvr_read_tsf(dvr_radio *r, uint64_t *out);

/* Stop everything, disarm the ACK responder, release the USB device and free
 * `r`. Safe to call with NULL. */
void dvr_close(dvr_radio *r);

#ifdef __cplusplus
}
#endif

#endif /* WARLOCK_DVR_SHIM_H */
