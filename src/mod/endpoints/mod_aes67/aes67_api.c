#include <switch.h>

#include <gst/app/gstappsink.h>
#include <gst/audio/audio-channels.h>
#include <gst/net/net.h>
#include "aes67_api.h"

#define ELEMENT_NAME_SIZE 20
#define STR_SIZE 15
#define NAME_ELEMENT(name, element, ch_idx) \
    g_snprintf(name, ELEMENT_NAME_SIZE, "%s-ch%u", element, ch_idx)

#define RTP_DEPAY "rx-depay"

#ifdef _WIN32
#define SYNTHETIC_CLOCK_INTERVAL_MS 1000
#else
#define SYNTHETIC_CLOCK_INTERVAL_MS 100
#endif

#define ENABLE_THREADSHARE
#define DEFAULT_CONTEXT_NAME "ts"
#define DEFAULT_CONTEXT_WAIT 10 // ms

#define MAKE_TS_ELEMENT(var, factory, name, context) \
  do { \
    var = gst_element_factory_make (factory, name); \
    g_object_set(var, "context-wait", DEFAULT_CONTEXT_WAIT, \
        "context", context, NULL); \
  } while (0)

typedef struct channel_remap channel_remap_t;

struct channel_remap {
  int channels;
  // map[input channel index] = output channel index;
  int map[MAX_IO_CHANNELS];
};

// Based on gst_rtp_channel_orders in gstrtpchannels.c
channel_remap_t channel_remaps[] = {
  {
    .channels = 5,
    .map = { 0, 1, 4, 2, 3 },
  },
};

static void
dump_pipeline (GstPipeline *pipe, const char *name)
{
  char *tmp = g_strdup_printf("%s-%s", gst_element_get_name(pipe), name);

  GST_DEBUG_BIN_TO_DOT_FILE (GST_BIN (pipe),
      GST_DEBUG_GRAPH_SHOW_ALL, tmp);

  g_free(tmp);
}

static gboolean
bus_callback (GstBus * bus, GstMessage * msg, gpointer data)
{

  g_stream_t *stream = (g_stream_t *) data;
  GstElement *pipeline = (GstElement *) stream->pipeline;
  switch (GST_MESSAGE_TYPE (msg)) {

    case GST_MESSAGE_EOS:
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
          "End of stream\n");
      gst_element_set_state (pipeline, GST_STATE_NULL);
      break;

    case GST_MESSAGE_ERROR:{
      gchar *debug;
      GError *error;

      gst_message_parse_error (msg, &error, &debug);
      g_free (debug);

      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error: %s\n",
          error->message);
      if (stream->error_cb)
        stream->error_cb (error->message, stream);
      g_error_free (error);

      gst_element_set_state (pipeline, GST_STATE_NULL);
      break;
    }
    case GST_MESSAGE_STATE_CHANGED:{
      GstState old, new, pending;
      GstPipeline *pipe = stream->pipeline;
      gst_message_parse_state_changed (msg, &old, &new, &pending);
      if (msg->src == (GstObject *) pipe) {
        gchar *old_state, *new_state, *transition;
        guint len = 0;
        old_state = g_strdup (gst_element_state_get_name (old));
        new_state = g_strdup (gst_element_state_get_name (new));
        len = strlen (old_state) + strlen (new_state) + strlen ("_to_") + 5;
        transition = g_malloc0 (len);
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
            "Pipeline %s changed state from %s to %s\n",
            GST_OBJECT_NAME (msg->src), old_state, new_state);
        g_snprintf (transition, len, "%s_to_%s", old_state, new_state);
        dump_pipeline(pipe, transition);
        g_free (old_state);
        g_free (new_state);
        g_free (transition);
      }
      break;
    }
    default:
      break;
  }

  return TRUE;

}

#ifdef ENABLE_THREADSHARE
static GstCaps *
request_pt_map(GstElement *jitterbuffer, guint pt, gpointer user_data)
{
  GstCaps *caps = GST_CAPS(user_data), *ret;

  ret = gst_caps_copy(caps);
  gst_caps_set_simple(ret, "payload", G_TYPE_INT, pt, NULL);

  return ret;
}

static void
destroy_caps(void *data, GClosure G_GNUC_UNUSED *closure)
{
  gst_caps_unref(data);
}
#endif

static void
deinterleave_pad_added (GstElement * deinterleave, GstPad * pad,
    gpointer userdata)
{
  GstElement *pipeline =
      GST_ELEMENT (gst_element_get_parent (deinterleave)), *queue;
  GstPad *queue_sink_pad;
  gchar name[ELEMENT_NAME_SIZE];
  gchar *pad_name;
  guint ch_idx;

  pad_name = gst_pad_get_name (pad);
  sscanf (pad_name, "src_%u", &ch_idx);

  NAME_ELEMENT (name, "rx-queue", ch_idx);
  queue = gst_bin_get_by_name (GST_BIN (pipeline), name);
  g_assert_nonnull (queue);

  queue_sink_pad = gst_element_get_static_pad (queue, "sink");

  if (gst_pad_link (pad, queue_sink_pad) != GST_PAD_LINK_OK) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to link deinterleave %s pad in the rx pipeline", pad_name);
  }

  dump_pipeline(GST_PIPELINE(pipeline), pad_name);

  gst_object_unref (queue_sink_pad);
  gst_object_unref(queue);
  gst_object_unref(pipeline);
  g_free (pad_name);
}

gboolean update_clock (gpointer userdata) {
  g_stream_t *stream = (g_stream_t *) userdata;
  GstStructure *stats = NULL;
  guint32 rtp_timestamp;
  GstElement *pipeline;
  GstClockTime internal, external;
  gdouble r_sq;
  GstElement *rtpdepay;

  pipeline = (GstElement *) stream->pipeline;
  rtpdepay = gst_bin_get_by_name (GST_BIN (pipeline), RTP_DEPAY);

  g_object_get (G_OBJECT(rtpdepay), "stats", &stats, NULL);

  if (gst_structure_get_uint(stats, "timestamp", &rtp_timestamp) ) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "rtp timestamp in rtpdepay %u\n", rtp_timestamp);

    internal = gst_clock_get_internal_time(stream->clock);
    external = gst_util_uint64_scale (rtp_timestamp, GST_SECOND, stream->sample_rate);

    if (gst_clock_add_observation(stream->clock, internal, external, &r_sq) &&
        !g_atomic_int_get (&stream->clock_sync)) {
      g_atomic_int_set(&stream->clock_sync, 1);

      gst_pipeline_use_clock (GST_PIPELINE (pipeline), stream->clock);
      gst_pipeline_set_clock (GST_PIPELINE (pipeline), stream->clock);
    }
  }

  gst_structure_free(stats);
  gst_object_unref (rtpdepay);

  return G_SOURCE_CONTINUE;
}

g_stream_t *
create_pipeline (pipeline_data_t *data, event_callback_t * error_cb)
{
  GstBus *bus;
  GstElement *pipeline, *rtp_pay = NULL, *rtpdepay = NULL, *rtpjitbuf = NULL;
  g_stream_t *stream = g_new (g_stream_t, 1);
  char fixed_name[25] = { "pipeline" };
  char *ts_ctx = DEFAULT_CONTEXT_NAME;
  char *pipeline_name;
  if (data->name)
    pipeline_name = data->name;
  else
    pipeline_name = fixed_name;

  if (0 != strlen(data->ts_context_name))
    ts_ctx = data->ts_context_name;

  pipeline = gst_pipeline_new (pipeline_name);
  if (!pipeline) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to create the pipeline\n");
    return NULL;
  }

  if (data->direction & DIRECTION_RX) {
    GstElement *udp_source, *appsink, *deinterleave, *rx_audioconv,
        *capsfilter, *queue, *valve, *split;
    GstCaps *udp_caps = NULL, *rx_caps = NULL;

#ifndef ENABLE_THREADSHARE
    udp_source = gst_element_factory_make ("udpsrc", "rx-src");
#else
    MAKE_TS_ELEMENT(udp_source, "ts-udpsrc", "rx-src", ts_ctx);
#endif
    g_object_set(udp_source, "buffer-size", 1048576, NULL);

    if (data->rx_codec == L16) {
      rtpdepay = gst_element_factory_make ("rtpL16depay", RTP_DEPAY);
      udp_caps = gst_caps_new_simple ("application/x-rtp",
          "clock-rate", G_TYPE_INT, data->sample_rate,
          "channels", G_TYPE_INT, data->channels,
          "channel-order", G_TYPE_STRING, "unpositioned",
          "encoding-name", G_TYPE_STRING, "L16",
          "media", G_TYPE_STRING, "audio", NULL);
    } else {
      rtpdepay = gst_element_factory_make ("rtpL24depay", RTP_DEPAY);
      udp_caps = gst_caps_new_simple ("application/x-rtp",
          "clock-rate", G_TYPE_INT, data->sample_rate,
          "channels", G_TYPE_INT, data->channels,
          "channel-order", G_TYPE_STRING, "unpositioned",
          "encoding-name", G_TYPE_STRING, "L24",
          "media", G_TYPE_STRING, "audio", NULL);
    }

#ifndef ENABLE_THREADSHARE
    rtpjitbuf = gst_element_factory_make("rtpjitterbuffer", "rx-jitbuf");
#else
    MAKE_TS_ELEMENT(rtpjitbuf, "ts-jitterbuffer", "rx-jitbuf", ts_ctx);
    g_signal_connect_data(rtpjitbuf, "request-pt-map", G_CALLBACK(request_pt_map),
        gst_caps_ref(udp_caps), destroy_caps, 0);
#endif
    g_object_set(rtpjitbuf, "latency", data->rtp_jitbuf_latency,
#ifndef ENABLE_THREADSHARE
        "mode", 0 /* none */,
#endif
        NULL);
    rx_audioconv = gst_element_factory_make ("audioconvert", "rx-aconv");
    g_object_set(rx_audioconv, "dithering", 0 /* none */, NULL);

    capsfilter = gst_element_factory_make ("capsfilter", "rx-caps");

    /*Always feed S16LE to the FS*/
    rx_caps = gst_caps_new_simple ("audio/x-raw",
        "channels", G_TYPE_INT, data->channels,
        "format", G_TYPE_STRING, "S16LE",
        "layout", G_TYPE_STRING, "interleaved", NULL);

    g_object_set (capsfilter, "caps", rx_caps, NULL);
    gst_caps_unref (rx_caps);

    split = gst_element_factory_make ("audiobuffersplit", "rx-split");
    g_object_set (split, "output-buffer-duration", data->codec_ms, 1000, NULL);

    deinterleave = gst_element_factory_make ("deinterleave", "rx-deinterleave");

    for (guint ch = 0; ch < data->channels; ch++) {
      gchar name[ELEMENT_NAME_SIZE];

      NAME_ELEMENT (name, "rx-queue", ch);
#ifndef ENABLE_THREADSHARE
      queue = gst_element_factory_make ("queue", name);
#else
      MAKE_TS_ELEMENT(queue, "ts-queue", name, ts_ctx);
#endif
      NAME_ELEMENT (name, "appsink", ch);
      appsink = gst_element_factory_make ("appsink", name);
      NAME_ELEMENT (name, "valve", ch);
      valve = gst_element_factory_make ("valve", name);

      if (!queue || !appsink || !valve) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to create receive elements");
        continue;
      }

      g_object_set (appsink, "emit-signals", FALSE, "sync", FALSE, "async", FALSE,
          "drop", TRUE, "max-buffers", 1, "enable-last-sample", FALSE, NULL);
      g_object_set (queue, "max-size-time", 100000000 /* 100 ms */ ,
#ifndef ENABLE_THREADSHARE
          "leaky", 2 /* downstream */,
#endif
          NULL);
      g_object_set (valve, "drop", TRUE, NULL);

      gst_bin_add (GST_BIN (pipeline), queue);
      gst_bin_add (GST_BIN (pipeline), valve);
      gst_bin_add (GST_BIN (pipeline), appsink);

      gst_element_link_many (queue, valve, appsink, NULL);

      // The deinterleave will be linked to the queue dynamically
    }

    g_signal_connect (deinterleave, "pad-added",
        G_CALLBACK (deinterleave_pad_added), NULL);

    g_object_set (udp_source, "address", data->rx_ip_addr, "port", data->rx_port,
        "multicast-iface", data->rtp_iface,
        "retrieve-sender-address", FALSE,
        NULL);
    g_object_set (udp_source, "caps", udp_caps, NULL);
    gst_caps_unref (udp_caps);

    if (!udp_source || !rtpdepay || !rtpjitbuf || !rx_audioconv || !capsfilter
        || !split || !deinterleave) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Failed to create rx elements\n");
      goto error;
    }

    gst_bin_add_many (GST_BIN (pipeline), udp_source, rtpdepay, rtpjitbuf, rx_audioconv,
        capsfilter, split, deinterleave, NULL);

    if (!gst_element_link_many (udp_source, rtpjitbuf, rtpdepay, split, rx_audioconv, capsfilter,
            deinterleave, NULL)) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Failed to link elements in the rx pipeline");
      goto error;
    }
  }

  if (data->direction & DIRECTION_TX) {
    GstElement *udpsink, *tx_audioconv, *audiointerleave, *capsfilter, *tx_valve;
    GstElement *appsrc;
    GstCaps *caps = NULL;

    audiointerleave =
        gst_element_factory_make ("audiointerleave", "audiointerleave");
    gst_bin_add (GST_BIN (pipeline), audiointerleave);
    g_object_set(audiointerleave, "start-time-selection", GST_AGGREGATOR_START_TIME_SELECTION_FIRST, NULL);
    g_object_set(audiointerleave, "output-buffer-duration", data->codec_ms * GST_MSECOND, NULL);

    if (data->tx_codec == L16) {
      rtp_pay = gst_element_factory_make ("rtpL16pay", "rtp-pay");

    } else {
      rtp_pay = gst_element_factory_make ("rtpL24pay", "rtp-pay");
    }
    g_object_set(rtp_pay, "pt", data->rtp_payload_type, NULL);

    if (data->ptime_ms != -1.0) {
      g_object_set(rtp_pay, "max-ptime", (gint64) (data->ptime_ms * 1000000),
          "min-ptime", (gint64) (data->ptime_ms * 1000000), NULL);
    }

    for (guint ch = 0; ch < data->channels; ch++) {
      gchar name[ELEMENT_NAME_SIZE];
      gchar pad_name[STR_SIZE];

      NAME_ELEMENT (name, "appsrc", ch);
      g_snprintf (pad_name, STR_SIZE, "sink_%u", ch);

      appsrc = gst_element_factory_make ("appsrc", name);
      if (!appsrc) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to create %s \n", name);
        continue;
      }

      /*Always accept S16LE from the FS*/
      caps = gst_caps_new_simple ("audio/x-raw",
          "rate", G_TYPE_INT, data->sample_rate,
          "channels", G_TYPE_INT, 1,
          "format", G_TYPE_STRING, "S16LE",
          "layout", G_TYPE_STRING, "interleaved",
          "channel-mask", GST_TYPE_BITMASK, (guint64) 0, NULL);
      g_object_set (appsrc, "format", GST_FORMAT_TIME, NULL);
      g_object_set (appsrc, "do-timestamp", TRUE, NULL);
      g_object_set (appsrc, "is-live", TRUE, NULL);
      /* Second * 3 allows a little bit of headroom */
      g_object_set (appsrc, "max-bytes", data->codec_ms * data->sample_rate * 2 * 3 / 1000,  NULL);

      g_object_set (appsrc, "caps", caps, NULL);
      gst_caps_unref (caps);
      gst_bin_add (GST_BIN (pipeline), appsrc);

      if (!gst_element_link_pads (appsrc, "src", audiointerleave, pad_name)) {
        switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
            "Failed to link pads of %s with audiointerleave\n", name);
        goto error;

      }
    }

    tx_valve = gst_element_factory_make ("valve", "tx-valve");
    g_object_set (tx_valve, "drop", data->txdrop, NULL);

    capsfilter = gst_element_factory_make ("capsfilter", "tx-capsf");

    tx_audioconv = gst_element_factory_make ("audioconvert", "tx-audioconv");
    g_object_set(tx_audioconv, "dithering", 0 /* none */, NULL);

    udpsink = gst_element_factory_make ("udpsink", "tx-sink");

    caps = gst_caps_new_simple ("audio/x-raw",
        "rate", G_TYPE_INT, data->sample_rate,
        "channels", G_TYPE_INT, data->channels,
        "format", G_TYPE_STRING, "S16LE",
        "layout", G_TYPE_STRING, "interleaved",
        "channel-mask", GST_TYPE_BITMASK, (guint64) 0,
        NULL);
    g_object_set (capsfilter, "caps", caps, NULL);
    gst_caps_unref (caps);

    g_object_set (udpsink, "host", data->tx_ip_addr, "port", data->tx_port, "multicast-iface", data->rtp_iface, NULL);
    g_object_set (udpsink, "sync", TRUE, "async", FALSE, NULL);
    g_object_set (udpsink, "qos", TRUE, "qos-dscp", 34, NULL);
    g_object_set (udpsink, "processing-deadline", 0 * GST_MSECOND, NULL);

    if (!audiointerleave || !tx_valve || !tx_audioconv || !rtp_pay || !udpsink) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Failed to create tx elements\n");
      goto error;
    }

    gst_bin_add_many (GST_BIN (pipeline), tx_valve, capsfilter, tx_audioconv, rtp_pay,
        udpsink, NULL);

    if (!gst_element_link_many (audiointerleave, tx_valve, capsfilter, tx_audioconv,
            rtp_pay, udpsink, NULL)) {
      switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
          "Failed to link elements");
      goto error;
    }
  }
  bus = gst_pipeline_get_bus (GST_PIPELINE (pipeline));
  gst_bus_add_watch (bus, bus_callback, stream);
  gst_object_unref (bus);

  stream->error_cb = error_cb;
  stream->pipeline = GST_PIPELINE (pipeline);
  stream->mainloop = g_main_loop_new (NULL, FALSE);
  stream->thread = g_thread_new (pipeline_name, start_pipeline, stream);
  stream->sample_rate = data->sample_rate;

  g_atomic_int_set (&stream->clock_sync, 0);

  gst_element_set_start_time(pipeline, GST_CLOCK_TIME_NONE);
  gst_element_set_base_time(pipeline, 0);

  if (rtp_pay) {
    /* We have data->codec_ms of latency in the audiointerleave, so add that in */
    /* FIXME: we should be cleverer and apply the pipeline latency as computed instead */
    g_object_set (rtp_pay, "timestamp-offset",
        gst_util_uint64_scale_int ((data->codec_ms + data->rtp_ts_offset) * GST_MSECOND, data->sample_rate, GST_SECOND)
          % G_MAXUINT32,
        NULL);
  }

  if (rtpdepay && data->synthetic_ptp) {
    stream->clock = g_object_new (GST_TYPE_SYSTEM_CLOCK, "name", "SyntheticPtpClock", NULL);
    stream->cb_rx_stats_id =
      g_timeout_add_full(G_PRIORITY_DEFAULT, SYNTHETIC_CLOCK_INTERVAL_MS, update_clock, stream, NULL);
    /* We'll set the pipeline clock once it's synced */
  } else {
    stream->clock = NULL;
    gst_pipeline_use_clock (GST_PIPELINE(pipeline), data->clock);
    g_atomic_int_set (&stream->clock_sync, 1);
  }

  for (guint ch = 0; ch < MAX_IO_CHANNELS; ch++)
    stream->leftover_bytes[ch] = 0;

  return stream;

error:
  gst_object_unref (pipeline);
  g_free (stream);
  return NULL;

}

void *
start_pipeline (void *data)
{
  g_stream_t *stream = (g_stream_t *) data;
  gst_element_set_state (GST_ELEMENT (stream->pipeline), GST_STATE_PLAYING);

  dump_pipeline(stream->pipeline, "start-pipeline");
  start_mainloop (stream->mainloop);
  return NULL;
}

void
stop_pipeline (g_stream_t * stream)
{
  GstBus *bus;

  dump_pipeline(stream->pipeline, "pipeline-stop");

  gst_element_set_state (GST_ELEMENT (stream->pipeline), GST_STATE_NULL);

  /* cb_rx_stats_id will be non zero only when
  Rx is operational and pipeline clock is not ptp*/
  if (stream->cb_rx_stats_id)
    g_source_remove(stream->cb_rx_stats_id);

  bus = gst_pipeline_get_bus (GST_PIPELINE (stream->pipeline));
  gst_bus_remove_watch (bus);
  gst_object_unref (bus);

  gst_object_unref (stream->pipeline);
  if (stream->clock)
    gst_object_unref (stream->clock);
  teardown_mainloop (stream->mainloop);
  g_thread_join (stream->thread);
  g_free (stream);
  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
      "Pipeline and mainloop cleaned up\n");

}

void
teardown_mainloop (GMainLoop * mainloop)
{

  g_main_loop_quit (mainloop);
  g_main_loop_unref (mainloop);
}


void
start_mainloop (GMainLoop * mainloop)
{

  switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Running mainloop\n");
  g_main_loop_run (mainloop);
}


gboolean
push_buffer (g_stream_t *stream, unsigned char *payload, guint len,
    guint ch_idx, switch_timer_t * timer)
{
  GstState cur_state = GST_STATE_NULL, pending_state;
  GstBuffer *buf;
  GstMapInfo info;
  GstFlowReturn ret;
  gchar name[ELEMENT_NAME_SIZE];
  GstElement *appsrc = NULL;
  GstPipeline *pipeline = stream->pipeline;
  gboolean res = FALSE;

  NAME_ELEMENT (name, "appsrc", ch_idx);
  appsrc = gst_bin_get_by_name (GST_BIN (pipeline), name);

  switch_core_timer_next (timer);

  if (appsrc == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
        "Failed to find appsrc in the pipeline\n");
    return FALSE;
  }

  if (!g_atomic_int_get(&stream->clock_sync)) {
    ret = TRUE;
    goto done;
  }

  gst_element_get_state (GST_ELEMENT (pipeline), &cur_state, &pending_state, 0);
  if (cur_state != GST_STATE_PAUSED && cur_state != GST_STATE_PLAYING) {
    ret = TRUE;
    goto done;
  }

  buf = gst_buffer_new_allocate (NULL, len, NULL);
  if (buf == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to allocate buffer\n");
    goto done;
  }

  if (!gst_buffer_map (buf, &info, GST_MAP_WRITE)) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to get buffer map\n");
    goto done;
  }
  memcpy (info.data, payload, len);
  gst_buffer_unmap (buf, &info);

  g_signal_emit_by_name (appsrc, "push-buffer", buf, &ret);
  // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Pushed buffer\n");

  gst_buffer_unref (buf);
  if (ret == GST_FLOW_ERROR) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to do 'push-buffer' \n");
    goto done;
  }

  res = TRUE;

done:
  gst_object_unref (GST_OBJECT (appsrc));
  return res;
}


int
pull_buffers (g_stream_t * stream, unsigned char *payload, guint needed_bytes,
    guint ch_idx, switch_timer_t * timer)
{
  GstState cur_state = GST_STATE_NULL, pending_state;
  GstBuffer *buf;
  GstSample *sample;
  GstMapInfo info;
  int total_bytes = 0;
  gchar name[ELEMENT_NAME_SIZE];
  GstElement *appsink;

  NAME_ELEMENT (name, "appsink", ch_idx);
  appsink = gst_bin_get_by_name (GST_BIN (stream->pipeline), name);

  if (appsink == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to find appsink in the pipeline\n");
    return 0;
  }

  gst_element_get_state (GST_ELEMENT (stream->pipeline), &cur_state,
      &pending_state, 0);
  if (cur_state != GST_STATE_PAUSED && cur_state != GST_STATE_PLAYING)
    goto out;

  if (gst_app_sink_is_eos (GST_APP_SINK (appsink)))
    goto out;

  // Note: assumes leftover_bytes will never be more than buflen, which is
  // likely true (packet is limited to MTU, while buflen is 8192)
  if (stream->leftover_bytes[ch_idx]) {
    int copy =
        stream->leftover_bytes[ch_idx] <=
        needed_bytes ? stream->leftover_bytes[ch_idx] : needed_bytes;
    memcpy (payload, stream->leftover[ch_idx], copy);
    total_bytes += copy;
    stream->leftover_bytes[ch_idx] -= copy;
  }

  while (total_bytes < needed_bytes) {
    // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "pulling buffer\n");
    sample =
        gst_app_sink_try_pull_sample (GST_APP_SINK (appsink),
        10 * GST_MSECOND);
    if (!sample) {
      // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Failed to pull sample\n");
      switch_cond_next ();
      break;
    }
    buf = gst_sample_get_buffer (sample);

    if (!buf)
      continue;

    if (gst_buffer_map (buf, &info, GST_MAP_READ)) {
      if (total_bytes + info.size > needed_bytes) {
        int want = needed_bytes - total_bytes;

        stream->leftover_bytes[ch_idx] = info.size - want;
        memcpy (stream->leftover[ch_idx], info.data + want,
            stream->leftover_bytes[ch_idx]);

        info.size = want;
      }

      memcpy (payload + total_bytes, info.data, info.size);
      total_bytes += info.size;
    }
    gst_buffer_unmap (buf, &info);
    gst_sample_unref (sample);

    // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Got %d\n", total_bytes);
  }

#if 0
  {
    // Dump data to file
    char name[100];
    int fd;

    NAME_ELEMENT (name, "/tmp/raw", ch_idx);
    fd = open (name, O_WRONLY | O_CREAT | O_APPEND);

    write (fd, payload, total_bytes);
    close (fd);
  }
#endif

  // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%u Returning needed %d, total_bytes: %d\n", ch_idx, needed_bytes, total_bytes);
  // switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Leftover %lu\n", stream->leftover_bytes[ch_idx]);

out:
  gst_object_unref(appsink);
  return total_bytes;
}


void
drop_input_buffers (gboolean drop, g_stream_t * stream, guint32 ch_idx)
{
  gchar name[ELEMENT_NAME_SIZE];
  GstElement *valve;
  NAME_ELEMENT (name, "valve", ch_idx);
  valve = gst_bin_get_by_name (GST_BIN (stream->pipeline), name);
  if (valve == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to get valve element in the pipeline\n");
    return;
  }
  g_object_set (valve, "drop", drop, NULL);
  g_snprintf (name, STR_SIZE, "drop-ch%d-%d", ch_idx, drop);
  dump_pipeline(stream->pipeline, name);
  gst_object_unref(valve);
}

gchar *
get_rtp_stats (g_stream_t *stream) {

  GstElement *rtpjitbuf;
  gchar *stats_str = NULL;
  rtpjitbuf = gst_bin_get_by_name(GST_BIN(stream->pipeline), "rx-jitbuf");

  if (rtpjitbuf) {
    GstStructure * stats;
    g_object_get(G_OBJECT(rtpjitbuf), "stats", &stats, NULL);
    stats_str = gst_structure_to_string (stats);
  }

  return stats_str;
}

void drop_output_buffers (gboolean drop, g_stream_t *stream)
{
  GstElement *tx_valve;
  gchar name[ELEMENT_NAME_SIZE];

  tx_valve = gst_bin_get_by_name(GST_BIN(stream->pipeline), "tx-valve");
  if (tx_valve == NULL) {
    switch_log_printf (SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
        "Failed to get valve element in the pipeline\n");
    return;
  }

  g_object_set (tx_valve, "drop", drop, NULL);

  g_snprintf (name, ELEMENT_NAME_SIZE, "tx-drop-%d", drop);
  dump_pipeline(stream->pipeline, name);

  gst_object_unref(tx_valve);
}