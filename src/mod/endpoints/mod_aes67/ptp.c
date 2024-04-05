/* GStreamer
 * Copyright (C) 2015 Sebastian Dröge <sebastian@centricular.com>
 *
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

/*
 * The code in this file is a modified version of the original code copied from
 * https://gitlab.freedesktop.org/gstreamer/gstreamer/subprojects/gstreamer/libs/gst/net/gstptpclock.c
 */

#include "ptp.h"
#include "switch.h"

/* IEEE 1588-2008 13.6 */
gboolean parse_ptp_message_sync(PtpMessage *msg, GstByteReader *reader, guint64 *timestamp)
{
	g_return_val_if_fail(msg->message_type == PTP_MESSAGE_TYPE_SYNC, FALSE);

	if (gst_byte_reader_get_remaining(reader) < 10) return FALSE;

	if (!parse_ptp_timestamp(&msg->message_specific.sync.origin_timestamp, reader)) return FALSE;

	*timestamp = msg->message_specific.sync.origin_timestamp.seconds_field * GST_SECOND +
				 msg->message_specific.sync.origin_timestamp.nanoseconds_field;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Sync time stamp is %llu\n", *timestamp);

	return TRUE;
}

/* IEEE 1588-2008 5.3.3 */
gboolean parse_ptp_timestamp(PtpTimestamp *timestamp, GstByteReader *reader)
{
	g_return_val_if_fail(gst_byte_reader_get_remaining(reader) >= 10, FALSE);

	timestamp->seconds_field = (((guint64)gst_byte_reader_get_uint32_be_unchecked(reader)) << 16) |
							   gst_byte_reader_get_uint16_be_unchecked(reader);
	timestamp->nanoseconds_field = gst_byte_reader_get_uint32_be_unchecked(reader);

	if (timestamp->nanoseconds_field >= 1000000000) return FALSE;

	return TRUE;
}

/* IEEE 1588-2008 13.3 */
gboolean parse_ptp_message_header(PtpMessage *msg, GstByteReader *reader)
{
	guint8 b;

	g_return_val_if_fail(gst_byte_reader_get_remaining(reader) >= 34, FALSE);

	b = gst_byte_reader_get_uint8_unchecked(reader);
	msg->transport_specific = b >> 4;
	msg->message_type = b & 0x0f;

	b = gst_byte_reader_get_uint8_unchecked(reader);
	msg->version_ptp = b & 0x0f;
	if (msg->version_ptp != 2) {
		// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Unsupported PTP message version (%u != 2)",
		// 				  msg->version_ptp);
		return FALSE;
	}

	msg->message_length = gst_byte_reader_get_uint16_be_unchecked(reader);
	if (gst_byte_reader_get_remaining(reader) + 4 < msg->message_length) {
		// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Not enough data (%u < %u)\n",
		// 				  gst_byte_reader_get_remaining(reader) + 4, msg->message_length);
		return FALSE;
	}

	msg->domain_number = gst_byte_reader_get_uint8_unchecked(reader);
	gst_byte_reader_skip_unchecked(reader, 1);

	msg->flag_field = gst_byte_reader_get_uint16_be_unchecked(reader);
	msg->correction_field = gst_byte_reader_get_uint64_be_unchecked(reader);
	gst_byte_reader_skip_unchecked(reader, 4);

	msg->source_port_identity.clock_identity = gst_byte_reader_get_uint64_be_unchecked(reader);
	msg->source_port_identity.port_number = gst_byte_reader_get_uint16_be_unchecked(reader);

	msg->sequence_id = gst_byte_reader_get_uint16_be_unchecked(reader);
	msg->control_field = gst_byte_reader_get_uint8_unchecked(reader);
	msg->log_message_interval = gst_byte_reader_get_uint8_unchecked(reader);

	return TRUE;
}

gboolean parse_ptp_message(PtpMessage *msg, const guint8 *data, gsize size, guint64 *timestamp)
{
	GstByteReader reader;
	gboolean ret = FALSE;

	gst_byte_reader_init(&reader, data, size);

	if (!parse_ptp_message_header(msg, &reader)) {
		// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Failed to parse PTP message header");
		return FALSE;
	}

	switch (msg->message_type) {
	case PTP_MESSAGE_TYPE_SYNC:
		ret = parse_ptp_message_sync(msg, &reader, timestamp);
		break;
	default:
		/* ignore for now */
		break;
	}

	return ret;
}