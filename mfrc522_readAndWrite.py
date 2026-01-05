import mfrc522
from os import uname


class MFRC522Reader:
    def __init__(self):
        self.buffer_uid = []
        self.buffer_test = 1
        self.rdr = self._initialize_reader()

    def _initialize_reader(self):
        """根据平台初始化MFRC522读卡器"""
        if uname()[0] == 'WiPy':
            return mfrc522.MFRC522("GP14", "GP16", "GP15", "GP22", "GP17")
        elif uname()[0] == 'esp8266':
            return mfrc522.MFRC522(0, 2, 4, 5, 14)
        elif uname()[0] == 'esp32':
            return mfrc522.MFRC522(4, 5, 6, 7, 15)
        else:
            raise RuntimeError("Unsupported platform")

    def do_read(self):
        """读取RFID卡信息"""
        print("")
        print("Place card before reader to read from address 0x08")
        print("")

        try:
            (stat, tag_type) = self.rdr.request(self.rdr.REQIDL)
            if stat == self.rdr.OK:
                (stat, raw_uid) = self.rdr.anticoll()
                if stat == self.rdr.OK:
                    print("New card detected")
                    print("  - tag type: 0x%02x" % tag_type)
                    print("  - uid     : 0x%02x%02x%02x%02x" %
                          (raw_uid[0], raw_uid[1], raw_uid[2], raw_uid[3]))
                    print("")
                    self.buffer_uid = raw_uid
                    if self.rdr.select_tag(raw_uid) == self.rdr.OK:
                        key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
                        if self.rdr.auth(self.rdr.AUTHENT1A, 8, key, raw_uid) == self.rdr.OK:
                            print("Address 8 data: %s" % self.rdr.read(8))
                            self.rdr.stop_crypto1()
                        else:
                            print("Authentication error")
                    else:
                        print("Failed to select tag")
        except KeyboardInterrupt:
            print("Bye")

    def do_write(self, data=None):
        """写入RFID卡信息"""
        if data is None:
            # 默认数据
            data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"

        print("")
        print("Place card before reader to write address 0x08")
        print("")

        try:
            (stat, tag_type) = self.rdr.request(self.rdr.REQIDL)

            if stat == self.rdr.OK:
                (stat, raw_uid) = self.rdr.anticoll()

                if stat == self.rdr.OK:
                    print("New card detected")
                    print("  - tag type: 0x%02x" % tag_type)
                    print("  - uid     : 0x%02x%02x%02x%02x" %
                          (raw_uid[0], raw_uid[1], raw_uid[2], raw_uid[3]))
                    print("")

                    if self.rdr.select_tag(raw_uid) == self.rdr.OK:
                        key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

                        if self.rdr.auth(self.rdr.AUTHENT1A, 8, key, raw_uid) == self.rdr.OK:
                            stat = self.rdr.write(8, data)
                            self.rdr.stop_crypto1()
                            if stat == self.rdr.OK:
                                print("Data written to card")
                            else:
                                print("Failed to write data to card")
                        else:
                            print("Authentication error")
                    else:
                        print("Failed to select tag")
        except KeyboardInterrupt:
            print("Bye")

    def write_uid_to_card_sector0(self, new_uid=None, sector0_key_a=None, sector0_key_b=None):
        """
        将UID写入到扇区0的块0（标准UID块）
        注意：这是一个高级操作，需要特殊类型的卡片支持（CUID/FUID卡）
        """
        if new_uid is None:
            if not self.buffer_uid:
                print("No UID in buffer and no UID provided.")
                return False
            new_uid = self.buffer_uid

        if len(new_uid) != 4:
            print("UID must be 4 bytes long")
            return False

        if sector0_key_a is None:
            sector0_key_a = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]  # 常见的扇区0密钥A
        if sector0_key_b is None:
            sector0_key_b = [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7]  # 常见的扇区0密钥B

        print("")
        print("Place card before reader to write UID to sector 0 block 0")
        print("WARNING: This operation may permanently modify the card UID")
        print("")

        try:
            (stat, tag_type) = self.rdr.request(self.rdr.REQIDL)
            if stat == self.rdr.OK:
                (stat, raw_uid) = self.rdr.anticoll()
                if stat == self.rdr.OK:
                    print("New card detected")
                    print("  - tag type: 0x%02x" % tag_type)
                    print("  - uid     : 0x%02x%02x%02x%02x" %
                          (raw_uid[0], raw_uid[1], raw_uid[2], raw_uid[3]))
                    print("")

                    if self.rdr.select_tag(raw_uid) == self.rdr.OK:
                        # 尝试使用密钥A进行认证
                        if self.rdr.auth(self.rdr.AUTHENT1A, 0, sector0_key_a, raw_uid) == self.rdr.OK:
                            # 构造新的块0数据（包含UID和校验）
                            new_block0 = self._create_block0_with_uid(new_uid)

                            print(f"Writing new UID {new_uid} to card block 0")
                            print(f"Block 0 data: {new_block0}")

                            stat = self.rdr.write(0, new_block0)
                            self.rdr.stop_crypto1()
                            if stat == self.rdr.OK:
                                print("New UID written to card successfully")
                                return True
                            else:
                                print("Failed to write UID to card")
                                return False
                        elif self.rdr.auth(self.rdr.AUTHENT1B, 0, sector0_key_b, raw_uid) == self.rdr.OK:
                            # 尝试使用密钥B进行认证
                            new_block0 = self._create_block0_with_uid(new_uid)

                            print(f"Writing new UID {new_uid} to card block 0")
                            print(f"Block 0 data: {new_block0}")

                            stat = self.rdr.write(0, new_block0)
                            self.rdr.stop_crypto1()
                            if stat == self.rdr.OK:
                                print("New UID written to card successfully")
                                return True
                            else:
                                print("Failed to write UID to card")
                                return False
                        else:
                            print("Authentication error - unable to access sector 0")
                            return False
                    else:
                        print("Failed to select tag")
                        return False
            else:
                print("No card detected")
                return False
        except KeyboardInterrupt:
            print("Operation cancelled by user")
            return False

    def _create_block0_with_uid(self, uid):
        """
        创建包含UID和校验的块0数据（MIFARE Classic格式）
        格式：UID (4字节) + BCC (1字节) + UID反向 (4字节) + BCC反向 (1字节) + 制造商数据 (6字节)
        位置：[0-3]   [4]     [5-8]      [9]        [10-15]
        """
        # 计算UID校验（BCC - Block Check Character）
        bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]

        # 创建块0数据
        block0 = bytearray(16)
        block0[0:4] = uid           # 原始UID (4字节)
        block0[4] = bcc             # UID校验 (1字节)
        block0[5:9] = uid[::-1]     # UID反向 (4字节)
        block0[9] = bcc ^ 0xFF      # BCC反向 (1字节)
        # 位置10-15是制造商数据和访问位，通常保持默认值
        block0[10] = 0x00  # 制造商字节
        block0[11] = 0x00  # 制造商字节
        block0[12] = 0x00  # 制造商字节
        block0[13] = 0x00  # 制造商字节
        block0[14] = 0x00  # 制造商字节
        block0[15] = 0x00  # 制造商字节

        return bytes(block0)

    def get_buffer_uid(self):
        """获取存储的UID"""
        return self.buffer_uid

    def set_buffer_test(self, value):
        """设置buffer_test值"""
        self.buffer_test = value

    def get_buffer_test(self):
        """获取buffer_test值"""
        return self.buffer_test
