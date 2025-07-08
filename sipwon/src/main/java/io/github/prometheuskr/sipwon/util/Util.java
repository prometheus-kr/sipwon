package io.github.prometheuskr.sipwon.util;

import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;

/**
 * Utility class providing various helper methods for string and byte array manipulation,
 * including hexadecimal conversions and odd parity calculations.
 * <p>
 * Features:
 * <ul>
 * <li>Conversion between byte arrays and hexadecimal strings</li>
 * <li>Odd parity calculation and conversion for byte arrays</li>
 * <li>String emptiness checks</li>
 * <li>Thread sleep utility</li>
 * </ul>
 * <p>
 * This class is not intended to be instantiated.
 * <p>
 * Logging is performed for debugging purposes during static initialization.
 */
@Slf4j
public class Util {
    /**
     * Utility class containing static helper methods.
     * <p>
     * This class is not intended to be instantiated.
     */
    private Util() {}

    /**
     * A lookup table containing hexadecimal string representations for all possible byte values (0-255).
     * Each index corresponds to the hexadecimal value of that byte, formatted as a two-character string (e.g., "00",
     * "1A", "FF").
     * Useful for efficient byte-to-hex string conversions.
     */
    private static final String[] HEX_TABLE = new String[256];
    /**
     * Lookup table containing precomputed odd parity values for all 256 possible byte values.
     * Each entry at index <code>i</code> represents the value of <code>i</code> adjusted to have odd parity.
     * Odd parity means the total number of 1-bits in the byte is odd.
     * This table can be used to efficiently enforce or check odd parity in byte-level operations.
     */
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

    /**
     * Checks if a given string is {@code null} or empty.
     *
     * @param str
     *            the string to check
     * @return {@code true} if the string is {@code null} or has a length of 0, {@code false} otherwise
     */
    public static boolean isEmpty(String str) {
        return str == null || str.isEmpty();
    }

    /**
     * Checks if the given string is not empty (not null and not zero-length).
     *
     * @param str
     *            the string to check
     * @return {@code true} if the string is not null and not empty, {@code false} otherwise
     */
    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * Converts the given byte array to its hexadecimal string representation.
     *
     * @param inputData
     *            the byte array to convert
     * @return a hexadecimal string representing the contents of the input byte array
     */
    public static String byteArray2HexaString(final byte[] inputData) {
        return byteArray2HexaString(inputData, 0, inputData.length);
    }

    /**
     * Converts a specified range of a byte array to its hexadecimal string representation.
     *
     * @param inputData
     *            the byte array to convert
     * @param offset
     *            the starting index in the array from which to begin conversion
     * @param length
     *            the number of bytes to convert starting from the offset
     * @return a string containing the hexadecimal representation of the specified byte range
     */
    public static String byteArray2HexaString(final byte[] inputData, final int offset, final int length) {
        StringBuffer result = new StringBuffer();
        for (int i = offset; i < offset + length; i++) {
            result.append(HEX_TABLE[inputData[i] & 0xFF]);
        }
        return result.toString();
    }

    /**
     * Converts a hexadecimal string into a byte array.
     * <p>
     * The input string must have an even length and contain only valid hexadecimal characters (0-9, a-f, A-F).
     * Each pair of hexadecimal characters is parsed into a single byte.
     *
     * @param hex
     *            the hexadecimal string to convert
     * @return a byte array representing the hexadecimal string
     * @throws NumberFormatException
     *             if the string contains invalid hexadecimal characters
     * @throws StringIndexOutOfBoundsException
     *             if the string length is not even
     */
    public static byte[] hexaString2ByteArray(final String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }

        return result;
    }

    /**
     * Causes the currently executing thread to sleep for the specified number of seconds.
     * If the thread is interrupted while sleeping, the interrupt status is set.
     *
     * @param seconds
     *            the number of seconds for which the thread should sleep
     */
    public static void sleep(int seconds) {
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException ignore) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Converts a hexadecimal string to a new hexadecimal string where each byte
     * is adjusted to have odd parity using a predefined parity table.
     * <p>
     * This method first converts the input hexadecimal string to a byte array,
     * then applies odd parity to each byte using the {@code ODD_PARITY_TABLE},
     * and finally converts the resulting byte array back to a hexadecimal string.
     *
     * @param hex
     *            the input hexadecimal string to be converted
     * @return a hexadecimal string where each byte has odd parity
     */
    public static String toOddParityHexString(String hex) {
        byte[] bytes = hexaString2ByteArray(hex);
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = ODD_PARITY_TABLE[bytes[i] & 0xFF];
        }
        return byteArray2HexaString(bytes);
    }
}
