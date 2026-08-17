#include <stdint.h>
#include <stddef.h>

#define SENSOR_COUNT 12
#define HISTORY_DEPTH 64
#define EVENT_CAPACITY 32
#define UART_BASE 0x10000000UL

typedef struct {
    uint32_t timestamp;
    int16_t values[SENSOR_COUNT];
    uint16_t status;
    uint16_t sequence;
} sensor_frame_t;

typedef struct {
    uint32_t code;
    uint32_t argument;
    uint32_t timestamp;
    uint32_t checksum;
} event_t;

typedef struct {
    int32_t minimum;
    int32_t maximum;
    int64_t sum;
    uint32_t samples;
} channel_statistics_t;

static volatile uint32_t system_ticks;
static sensor_frame_t frame_history[HISTORY_DEPTH];
static event_t event_queue[EVENT_CAPACITY];
static channel_statistics_t statistics[SENSOR_COUNT];
static uint32_t history_write_index;
static uint32_t event_read_index;
static uint32_t event_write_index;
static int32_t filtered_values[SENSOR_COUNT];
static uint16_t frame_sequence;
static uint32_t dropped_events;
static const int16_t filter_coefficients[12] = {1, 2, 4, 7, 10, 12, 12, 10, 7, 4, 2, 1};
static const char firmware_banner[] = "RVFPA demonstration firmware V2";

static void uart_write_byte(uint8_t value) {
    volatile uint8_t *uart = (volatile uint8_t *)UART_BASE;
    *uart = value;
}

static void uart_write_text(const char *text) {
    while (*text) uart_write_byte((uint8_t)*text++);
}

static void uart_write_hex(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    for (int shift = 28; shift >= 0; shift -= 4) uart_write_byte((uint8_t)digits[(value >> shift) & 15U]);
}

static uint32_t crc32_update(uint32_t crc, uint8_t value) {
    crc ^= value;
    for (unsigned bit = 0; bit < 8; ++bit) {
        uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
        crc = (crc >> 1) ^ (0xedb88320U & mask);
    }
    return crc;
}

static uint32_t crc32_buffer(const void *buffer, size_t length) {
    const uint8_t *bytes = (const uint8_t *)buffer;
    uint32_t crc = 0xffffffffU;
    for (size_t index = 0; index < length; ++index) crc = crc32_update(crc, bytes[index]);
    return ~crc;
}

static int16_t saturate_i16(int32_t value) {
    if (value > 32767) return 32767;
    if (value < -32768) return -32768;
    return (int16_t)value;
}

static int32_t absolute_i32(int32_t value) {
    return value < 0 ? -value : value;
}

static void acquire_sensor_frame(sensor_frame_t *frame) {
    frame->timestamp = system_ticks;
    frame->status = 0;
    frame->sequence = frame_sequence++;
    for (unsigned channel = 0; channel < SENSOR_COUNT; ++channel) {
        uint32_t phase = system_ticks * (channel + 1U) + channel * 29U;
        int32_t triangle = (int32_t)(phase & 255U);
        if (triangle > 127) triangle = 255 - triangle;
        int32_t sample = (triangle - 63) * (int32_t)(channel + 1);
        frame->values[channel] = saturate_i16(sample);
        if (absolute_i32(sample) > 600) frame->status |= (uint16_t)(1U << channel);
    }
}

static void apply_sensor_filter(unsigned channel) {
    int32_t accumulator = 0;
    for (unsigned tap = 0; tap < 12; ++tap) {
        uint32_t position = (history_write_index + HISTORY_DEPTH - tap) % HISTORY_DEPTH;
        accumulator += frame_history[position].values[channel] * filter_coefficients[tap];
    }
    filtered_values[channel] = saturate_i16(accumulator / 72);
}

static void update_statistics(unsigned channel, int32_t value) {
    channel_statistics_t *item = &statistics[channel];
    if (item->samples == 0 || value < item->minimum) item->minimum = value;
    if (item->samples == 0 || value > item->maximum) item->maximum = value;
    item->sum += value;
    item->samples++;
}

static uint32_t event_checksum(const event_t *event) {
    return event->code ^ event->argument ^ event->timestamp ^ 0x5aa55aa5U;
}

static int enqueue_event(uint32_t code, uint32_t argument) {
    uint32_t next = (event_write_index + 1U) % EVENT_CAPACITY;
    if (next == event_read_index) {
        dropped_events++;
        return -1;
    }
    event_t *event = &event_queue[event_write_index];
    event->code = code;
    event->argument = argument;
    event->timestamp = system_ticks;
    event->checksum = event_checksum(event);
    event_write_index = next;
    return 0;
}

static int dequeue_event(event_t *event) {
    if (event_read_index == event_write_index) return -1;
    *event = event_queue[event_read_index];
    event_read_index = (event_read_index + 1U) % EVENT_CAPACITY;
    return event->checksum == event_checksum(event) ? 0 : -2;
}

static void transmit_frame(const sensor_frame_t *frame) {
    const uint8_t *bytes = (const uint8_t *)frame;
    uint32_t checksum = crc32_buffer(frame, sizeof(*frame));
    uart_write_byte(0x7e);
    for (size_t index = 0; index < sizeof(*frame); ++index) uart_write_byte(bytes[index]);
    for (unsigned shift = 0; shift < 32; shift += 8) uart_write_byte((uint8_t)(checksum >> shift));
}

static void report_statistics(void) {
    uart_write_text("statistics:");
    for (unsigned channel = 0; channel < SENSOR_COUNT; ++channel) {
        channel_statistics_t *item = &statistics[channel];
        int32_t average = item->samples ? (int32_t)(item->sum / item->samples) : 0;
        uart_write_byte(' ');
        uart_write_hex((uint32_t)average);
    }
    uart_write_text("\n");
}

static void process_events(void) {
    event_t event;
    int result;
    while ((result = dequeue_event(&event)) != -1) {
        if (result == -2) {
            uart_write_text("bad-event\n");
        } else if (event.code == 1) {
            uart_write_text("threshold\n");
        } else if (event.code == 2) {
            uart_write_text("telemetry\n");
        } else if (event.code == 3) {
            report_statistics();
        } else {
            uart_write_text("event\n");
        }
    }
}

static void scheduler_step(void) {
    sensor_frame_t frame;
    acquire_sensor_frame(&frame);
    history_write_index = (history_write_index + 1U) % HISTORY_DEPTH;
    frame_history[history_write_index] = frame;
    for (unsigned channel = 0; channel < SENSOR_COUNT; ++channel) {
        apply_sensor_filter(channel);
        update_statistics(channel, filtered_values[channel]);
    }
    if (frame.status) enqueue_event(1, frame.status);
    if ((system_ticks & 31U) == 0) {
        enqueue_event(2, history_write_index);
        transmit_frame(&frame);
    }
    if ((system_ticks & 255U) == 0) enqueue_event(3, dropped_events);
    process_events();
}

int main(void) {
    uart_write_text(firmware_banner);
    uart_write_text("\n");
    for (;;) {
        ++system_ticks;
        scheduler_step();
        if (system_ticks == 4096U) system_ticks = 0;
    }
}

