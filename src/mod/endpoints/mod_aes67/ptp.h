#include <gst/gst.h>
#include <gst/base/base.h>


typedef enum
{
  PTP_MESSAGE_TYPE_SYNC = 0x0,
  PTP_MESSAGE_TYPE_DELAY_REQ = 0x1,
  PTP_MESSAGE_TYPE_PDELAY_REQ = 0x2,
  PTP_MESSAGE_TYPE_PDELAY_RESP = 0x3,
  PTP_MESSAGE_TYPE_FOLLOW_UP = 0x8,
  PTP_MESSAGE_TYPE_DELAY_RESP = 0x9,
  PTP_MESSAGE_TYPE_PDELAY_RESP_FOLLOW_UP = 0xA,
  PTP_MESSAGE_TYPE_ANNOUNCE = 0xB,
  PTP_MESSAGE_TYPE_SIGNALING = 0xC,
  PTP_MESSAGE_TYPE_MANAGEMENT = 0xD
} PtpMessageType;

typedef struct
{
  guint64 seconds_field;        /* 48 bits valid */
  guint32 nanoseconds_field;
} PtpTimestamp;

#define PTP_TIMESTAMP_TO_GST_CLOCK_TIME(ptp) (ptp.seconds_field * GST_SECOND + ptp.nanoseconds_field)
#define GST_CLOCK_TIME_TO_PTP_TIMESTAMP_SECONDS(gst) (((GstClockTime) gst) / GST_SECOND)
#define GST_CLOCK_TIME_TO_PTP_TIMESTAMP_NANOSECONDS(gst) (((GstClockTime) gst) % GST_SECOND)

typedef struct
{
  guint64 clock_identity;
  guint16 port_number;
} PtpClockIdentity;

// static gint
// compare_clock_identity (const PtpClockIdentity * a, const PtpClockIdentity * b)
// {
//   if (a->clock_identity < b->clock_identity)
//     return -1;
//   else if (a->clock_identity > b->clock_identity)
//     return 1;

//   if (a->port_number < b->port_number)
//     return -1;
//   else if (a->port_number > b->port_number)
//     return 1;

//   return 0;
// }

typedef struct
{
  guint8 clock_class;
  guint8 clock_accuracy;
  guint16 offset_scaled_log_variance;
} PtpClockQuality;

typedef struct
{
  guint8 transport_specific;
  PtpMessageType message_type;
  /* guint8 reserved; */
  guint8 version_ptp;
  guint16 message_length;
  guint8 domain_number;
  /* guint8 reserved; */
  guint16 flag_field;
  gint64 correction_field;      /* 48.16 fixed point nanoseconds */
  /* guint32 reserved; */
  PtpClockIdentity source_port_identity;
  guint16 sequence_id;
  guint8 control_field;
  gint8 log_message_interval;

  union
  {
    struct
    {
      PtpTimestamp origin_timestamp;
      gint16 current_utc_offset;
      /* guint8 reserved; */
      guint8 grandmaster_priority_1;
      PtpClockQuality grandmaster_clock_quality;
      guint8 grandmaster_priority_2;
      guint64 grandmaster_identity;
      guint16 steps_removed;
      guint8 time_source;
    } announce;

    struct
    {
      PtpTimestamp origin_timestamp;
    } sync;

    struct
    {
      PtpTimestamp precise_origin_timestamp;
    } follow_up;

    struct
    {
      PtpTimestamp origin_timestamp;
    } delay_req;

    struct
    {
      PtpTimestamp receive_timestamp;
      PtpClockIdentity requesting_port_identity;
    } delay_resp;

  } message_specific;
} PtpMessage;