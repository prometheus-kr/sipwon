package io.github.prometheuskr.sipwon.util;

import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Util {
    private Util() {
    }

    private static final String[] HEX_TABLE = new String[256];
    private static final byte[] ODD_PARITY_TABLE = new byte[256];

    static {
        for (int i = 0; i < 256; i++) {
            HEX_TABLE[i] = String.format("%02X", i);
        }
        if (log.isDebugEnabled())
            log.debug("HEX_TABLE[{}] = {}", Arrays.toString(HEX_TABLE));

        for (int i = 0; i < 256; i++) {
            int b = i & 0xFE;
            int ones = Integer.bitCount(b);
            // 홀수 패리티가 아니면 LSB(최하위 비트)를 반전
            ODD_PARITY_TABLE[i] = (byte) ((ones % 2) == (i & 0x01) ? (i ^ 0x01) : i);
        }
        if (log.isDebugEnabled())
            log.debug("hex ODD_PARITY_TABLE[{}] = {}", byteArray2HexaString(ODD_PARITY_TABLE));
    }

    public static boolean isEmpty(String str) {
        return str == null || str.isEmpty();
    }

    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    public static String byteArray2HexaString(final byte[] inputData) {
        return byteArray2HexaString(inputData, 0, inputData.length);
    }

    public static String byteArray2HexaString(final byte[] inputData, final int offset, final int length) {
        StringBuffer result = new StringBuffer();
        for (int i = offset; i < offset + length; i++) {
            result.append(HEX_TABLE[inputData[i] & 0xFF]);
        }
        return result.toString();
    }

    public static byte[] hexaString2ByteArray(final String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }

        return result;
    }

    public static void sleep(int seconds) {
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException ignore) {
            Thread.currentThread().interrupt();
        }
    }

    public static String toOddParityHexString(String hex) {
        byte[] bytes = hexaString2ByteArray(hex);
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = ODD_PARITY_TABLE[bytes[i] & 0xFF];
        }
        return byteArray2HexaString(bytes);
    }
}
