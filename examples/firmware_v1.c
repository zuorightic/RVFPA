#include <stdint.h>
#include <stddef.h>

#define SENSOR_COUNT 8
#define HISTORY_DEPTH 32
#define EVENT_CAPACITY 16
#define UART_BASE 0x10000000UL

typedef struct {
    uint32_t timestamp;
    int16_t values[SENSOR_COUNT];
    uint16_t status;
} sensor_frame_t;

typedef struct {
    uint32_t code;
    uint32_t argument;
    uint32_t timestamp;
} event_t;

static volatile uint32_t system_ticks;
static sensor_frame_t frame_history[HISTORY_DEPTH];
static event_t event_queue[EVENT_CAPACITY];
static uint32_t history_write_index;
static uint32_t event_read_index;
static uint32_t event_write_index;
static int32_t filtered_values[SENSOR_COUNT];
static const int16_t filter_coefficients[8] = {2, 5, 9, 14, 14, 9, 5, 2};
static const char firmware_banner[] = "RVFPA demonstration firmware V1";

static void uart_write_byte(uint8_t value) {
    volatile uint8_t *uart = (volatile uint8_t *)UART_BASE;
    *uart = value;
}

static void uart_write_text(const char *text) {
    while (*text) {
        uart_write_byte((uint8_t)*text++);
    }
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
    for (size_t index = 0; index < length; ++index) {
        crc = crc32_update(crc, bytes[index]);
    }
    return ~crc;
}

static int16_t saturate_i16(int32_t value) {
    if (value > 32767) return 32767;
    if (value < -32768) return -32768;
    return (int16_t)value;
}

static void acquire_sensor_frame(sensor_frame_t *frame) {
    frame->timestamp = system_ticks;
    frame->status = 0;
    for (unsigned channel = 0; channel < SENSOR_COUNT; ++channel) {
        uint32_t phase = system_ticks + channel * 17U;
        int32_t triangle = (int32_t)(phase & 127U);
        if (triangle > 63) triangle = 127 - triangle;
        frame->values[channel] = (int16_t)(triangle * (int32_t)(channel + 1));
        if (frame->values[channel] > 350) frame->status |= (uint16_t)(1U << channel);
    }
}

static void apply_sensor_filter(unsigned channel) {
    int32_t accumulator = 0;
    for (unsigned tap = 0; tap < 8; ++tap) {
        uint32_t position = (history_write_index + HISTORY_DEPTH - tap) % HISTORY_DEPTH;
        accumulator += frame_history[position].values[channel] * filter_coefficients[tap];
    }
    filtered_values[channel] = saturate_i16(accumulator / 60);
}

static int enqueue_event(uint32_t code, uint32_t argument) {
    uint32_t next = (event_write_index + 1U) % EVENT_CAPACITY;
    if (next == event_read_index) return -1;
    event_queue[event_write_index].code = code;
    event_queue[event_write_index].argument = argument;
    event_queue[event_write_index].timestamp = system_ticks;
    event_write_index = next;
    return 0;
}

static int dequeue_event(event_t *event) {
    if (event_read_index == event_write_index) return -1;
    *event = event_queue[event_read_index];
    event_read_index = (event_read_index + 1U) % EVENT_CAPACITY;
    return 0;
}

static void transmit_frame(const sensor_frame_t *frame) {
    const uint8_t *bytes = (const uint8_t *)frame;
    uint32_t checksum = crc32_buffer(frame, sizeof(*frame));
    uart_write_byte(0x7e);
    for (size_t index = 0; index < sizeof(*frame); ++index) uart_write_byte(bytes[index]);
    for (unsigned shift = 0; shift < 32; shift += 8) uart_write_byte((uint8_t)(checksum >> shift));
}

static void process_events(void) {
    event_t event;
    while (dequeue_event(&event) == 0) {
        if (event.code == 1) {
            uart_write_text("threshold\n");
        } else if (event.code == 2) {
            uart_write_text("telemetry\n");
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
    for (unsigned channel = 0; channel < SENSOR_COUNT; ++channel) apply_sensor_filter(channel);
    if (frame.status) enqueue_event(1, frame.status);
    if ((system_ticks & 31U) == 0) {
        enqueue_event(2, history_write_index);
        transmit_frame(&frame);
    }
    process_events();
}

int main(void) {
    uart_write_text(firmware_banner);
    uart_write_text("\n");
    for (;;) {
        ++system_ticks;
        scheduler_step();
        if (system_ticks == 1024U) system_ticks = 0;
    }
}

