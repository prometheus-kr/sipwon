package io.github.prometheuskr.sipwon.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class UtilTest {
    @Test
    void byteArray2HexaString_basic() {
        byte[] input = { (byte) 0x01, (byte) 0xAB, (byte) 0xFF };
        String hex = Util.byteArray2HexaString(input);
        assertEquals("01ABFF", hex);
    }

    @Test
    void byteArray2HexaString_withOffsetAndLength() {
        byte[] input = { (byte) 0x00, (byte) 0x12, (byte) 0x34, (byte) 0x56 };
        String hex = Util.byteArray2HexaString(input, 1, 2);
        assertEquals("1234", hex);
    }

    @Test
    void byteArray2HexaString_empty() {
        byte[] input = {};
        String hex = Util.byteArray2HexaString(input);
        assertEquals("", hex);
    }

    @Test
    void byteArray2HexaString_negativeBytes() {
        byte[] input = { (byte) 0x80, (byte) 0xFF };
        String hex = Util.byteArray2HexaString(input);
        assertEquals("80FF", hex);
    }

    @Test
    void byteArray2HexaString_fullRange() {
        byte[] input = new byte[256];
        for (int i = 0; i < 256; i++)
            input[i] = (byte) i;
        String hex = Util.byteArray2HexaString(input);
        StringBuilder expected = new StringBuilder();
        for (int i = 0; i < 256; i++) {
            String h = Integer.toHexString(i).toUpperCase();
            if (h.length() == 1)
                expected.append('0');
            expected.append(h);
        }
        assertEquals(expected.toString(), hex);
    }
}
