#include "lcd_sh1106.h"
#include <string.h>
#include "esp_log.h"
#include "esp_check.h"
#include "driver/i2c_master.h"
#include "driver/gpio.h"
#include "esp_lcd_panel_sh1106.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"

#include "qrcodegen.h"

#define I2C_SDA_GPIO GPIO_NUM_13
#define I2C_SCL_GPIO GPIO_NUM_14
#define I2C_HOST I2C_NUM_0

// Biến lưu panel handle để dùng lại
static esp_lcd_panel_handle_t panel_handle = NULL;

void lcd_sh1106_init(void)
{
    i2c_master_bus_config_t bus_config = {
        .i2c_port = I2C_HOST,
        .sda_io_num = I2C_SDA_GPIO,
        .scl_io_num = I2C_SCL_GPIO,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .intr_priority = 0,
        .trans_queue_depth = 0,
        .flags = {
            .enable_internal_pullup = true,
        },
    };

    i2c_master_bus_handle_t i2c_bus_handle = NULL;
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_config, &i2c_bus_handle));

    esp_lcd_panel_io_handle_t io_handle = NULL;
    esp_lcd_panel_io_i2c_config_t io_config = ESP_SH1106_DEFAULT_IO_CONFIG;
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c(i2c_bus_handle, &io_config, &io_handle));

    esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = -1,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB,
        .data_endian = LCD_RGB_DATA_ENDIAN_LITTLE,
        .bits_per_pixel = SH1106_PIXELS_PER_BYTE / 8,
        .flags = {
            .reset_active_high = false,
        },
        .vendor_config = NULL,
    };

    ESP_ERROR_CHECK(esp_lcd_new_panel_sh1106(io_handle, &panel_config, &panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_handle, true));
}

void draw_rectangle(uint8_t *buffer, int x, int y, int w, int h, bool fill)
{
    for (int j = 0; j < h; j++) {
        for (int i = 0; i < w; i++) {
            int px = x + i;
            int py = y + j;
            if (px < 0 || px >= SH1106_WIDTH || py < 0 || py >= SH1106_HEIGHT) continue;

            int byte_index = px + (py / 8) * SH1106_WIDTH;
            int bit_mask = 1 << (py % 8);

            if (fill || j == 0 || j == h - 1 || i == 0 || i == w - 1) {
                buffer[byte_index] |= bit_mask;
            }
        }
    }
}

void lcd_sh1106_draw_screen(bool fill)
{
    uint8_t buffer_data[SH1106_BUFFER_SIZE];
    memset(buffer_data, 0, SH1106_BUFFER_SIZE);

    draw_rectangle(buffer_data, 0, 0, 128, 64, fill);

    ESP_ERROR_CHECK(esp_lcd_panel_draw_bitmap(panel_handle, 0, 0, SH1106_WIDTH, SH1106_HEIGHT, buffer_data));
}


void draw_char(uint8_t *buffer, int x, int y, char c)
{
    if (c < 32 || c > 127) return;
    const uint8_t *glyph = font8x8_basic_tr[c - 32];

    for (int col = 0; col < 8; col++) {
        uint8_t bits = glyph[col];
        for (int row = 0; row < 8; row++) {
            if (bits & (1 << row)) {
                int px = x + col;
                int py = y + row;
                if (px < 0 || px >= SH1106_WIDTH || py < 0 || py >= SH1106_HEIGHT) continue;
                int index = px + (py / 8) * SH1106_WIDTH;
                buffer[index] |= (1 << (py % 8));
            }
        }
    }
}

void lcd_sh1106_draw_text(int start_x, int start_y, const char *text)
{
    uint8_t buffer_data[SH1106_BUFFER_SIZE];
    memset(buffer_data, 0, sizeof(buffer_data));

    int x = start_x;
    int y = start_y;

    const int CHAR_WIDTH = 8;
    const int CHAR_HEIGHT = 8;

    while (*text) {
        char c = *text++;

        // Nếu xuống dòng thủ công
        if (c == '\n') {
            x = start_x;
            y += CHAR_HEIGHT;
            if (y + CHAR_HEIGHT > SH1106_HEIGHT) break;
            continue;
        }

        // Nếu vượt chiều ngang màn hình, tự xuống dòng
        if (x + CHAR_WIDTH > SH1106_WIDTH) {
            x = start_x;
            y += CHAR_HEIGHT;
            if (y + CHAR_HEIGHT > SH1106_HEIGHT) break;
        }

        // Vẽ ký tự
        if ((uint8_t)c < 128) {
            for (int col = 0; col < CHAR_WIDTH; col++) {
                uint8_t line = font8x8_basic_tr[(uint8_t)c][col];
                for (int row = 0; row < CHAR_HEIGHT; row++) {
                    if (line & (1 << row)) {
                        int px = x + col;
                        int py = y + row;
                        if (px < 0 || px >= SH1106_WIDTH || py < 0 || py >= SH1106_HEIGHT) continue;

                        int byte_index = px + (py / 8) * SH1106_WIDTH;
                        int bit_mask = 1 << (py % 8);
                        buffer_data[byte_index] |= bit_mask;
                    }
                }
            }
        }

        x += CHAR_WIDTH;
    }

    // Gửi toàn bộ buffer lên màn hình
    ESP_ERROR_CHECK(esp_lcd_panel_draw_bitmap(panel_handle, 0, 0, SH1106_WIDTH, SH1106_HEIGHT, buffer_data));
}


void lcd_sh1106_draw_text_and_qr(int text_x, int text_y, const char* text, int qr_x, int qr_y, const char* qr_data, int qr_scale) {
    uint8_t buffer[SH1106_BUFFER_SIZE];
    memset(buffer, 0, sizeof(buffer));

    // --- Tạo QR ---
    uint8_t temp[400], qr[400];
    qrcodegen_encodeText(qr_data, temp, qr, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                         qrcodegen_Mask_AUTO, true);

    int qr_size = qrcodegen_getSize(qr);

    // --- Vẽ QR ---
    for (int y = 0; y < qr_size; y++) {
        for (int x = 0; x < qr_size; x++) {
            if (qrcodegen_getModule(qr, x, y)) {
                for (int dy = 0; dy < qr_scale; dy++) {
                    for (int dx = 0; dx < qr_scale; dx++) {
                        int px = qr_x + x * qr_scale + dx;
                        int py = qr_y + y * qr_scale + dy;
                        if (px >= 0 && px < SH1106_WIDTH && py >= 0 && py < SH1106_HEIGHT) {
                            int byte_index = px + (py / 8) * SH1106_WIDTH;
                            int bit_mask = 1 << (py % 8);
                            buffer[byte_index] |= bit_mask;
                        }
                    }
                }
            }
        }
    }

    // --- Vẽ Text ---
    text_x = qr_size*qr_scale + 8;
    int x = text_x;
    int y = text_y;

    const int CHAR_WIDTH = 8;
    const int CHAR_HEIGHT = 8;

    while (*text) {
        char c = *text++;

        // Nếu xuống dòng thủ công
        if (c == '\n') {
            x = text_x;
            y += CHAR_HEIGHT;
            if (y + CHAR_HEIGHT > SH1106_HEIGHT) break;
            continue;
        }

        // Nếu vượt chiều ngang màn hình, tự xuống dòng
        if (x + CHAR_WIDTH > SH1106_WIDTH) {
            x = text_x;
            y += CHAR_HEIGHT;
            if (y + CHAR_HEIGHT > SH1106_HEIGHT) break;
        }

        // Vẽ ký tự
        if ((uint8_t)c < 128) {
            for (int col = 0; col < CHAR_WIDTH; col++) {
                uint8_t line = font8x8_basic_tr[(uint8_t)c][col];
                for (int row = 0; row < CHAR_HEIGHT; row++) {
                    if (line & (1 << row)) {
                        int px = x + col;
                        int py = y + row;
                        if (px < 0 || px >= SH1106_WIDTH || py < 0 || py >= SH1106_HEIGHT) continue;

                        int byte_index = px + (py / 8) * SH1106_WIDTH;
                        int bit_mask = 1 << (py % 8);
                        buffer[byte_index] |= bit_mask;
                    }
                }
            }
        }

        x += CHAR_WIDTH;
    }

    // --- Hiển thị ---
    esp_lcd_panel_draw_bitmap(panel_handle, 0, 0, SH1106_WIDTH, SH1106_HEIGHT, buffer);
}







