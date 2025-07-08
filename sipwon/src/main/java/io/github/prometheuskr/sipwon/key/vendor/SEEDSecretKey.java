package io.github.prometheuskr.sipwon.key.vendor;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.GenericSecretKey;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import io.github.prometheuskr.sipwon.constant.HsmVendorKeyType;

/**
 * Represents a SEED secret key for use with PKCS#11 HSMs, supporting vendor-defined key types.
 * <p>
 * This class extends {@link GenericSecretKey} and provides SEED-specific key handling,
 * including attribute allocation, cloning, and equality checks. It manages the key value
 * as a {@link ByteArrayAttribute} and integrates with vendor-specific key builders.
 * <p>
 * Typical usage involves instantiating this class via the static {@code getInstance} method,
 * which retrieves a SEED secret key from a PKCS#11 session and object handle.
 * <p>
 * The class also overrides {@code clone}, {@code equals}, and {@code toString} to ensure
 * correct behavior for SEED secret keys.
 * 
 * @see GenericSecretKey
 * @see ByteArrayAttribute
 * @see HsmVendorKeyType
 * @see Session
 */
public class SEEDSecretKey extends GenericSecretKey {

    /**
     * A {@link VendorDefinedKeyBuilder} implementation that creates a {@link SEEDSecretKey}
     * instance using the provided session and handle. If a {@link TokenException} occurs
     * during instantiation, it throws a {@link PKCS11Exception} with a custom error code.
     *
     * @see SEEDSecretKey#getInstance(long, long)
     * @see TokenException
     * @see PKCS11Exception
     */
    private final VendorDefinedKeyBuilder builder = (s, h) -> {
        try {
            return SEEDSecretKey.getInstance(s, h);
        } catch (TokenException e) {
            throw new PKCS11Exception(0x88000001l);
        }
    };

    /**
     * The value of the secret key as a byte array attribute.
     * This typically contains the raw key material used for cryptographic operations.
     */
    protected ByteArrayAttribute value_;

    /**
     * Constructs a new SEEDSecretKey instance.
     * <p>
     * Initializes the key type to the SEED algorithm as defined by the HSM vendor,
     * and sets up the vendor-specific key builder.
     */
    public SEEDSecretKey() {
        super();
        keyType_.setLongValue(HsmVendorKeyType.SEED.getKeyType());
        vendorKeyBuilder_ = builder;
    }

    /**
     * Constructs a SEEDSecretKey object associated with the given session and object handle.
     * Initializes the key type to SEED as defined by the vendor-specific key type enumeration.
     *
     * @param session
     *            the session associated with this key
     * @param objectHandle
     *            the handle identifying the key object within the HSM
     * @throws TokenException
     *             if an error occurs during key initialization or retrieval
     */
    protected SEEDSecretKey(final Session session, final long objectHandle) throws TokenException {
        super(session, objectHandle);
        keyType_.setLongValue(HsmVendorKeyType.SEED.getKeyType());
        vendorKeyBuilder_ = builder;
    }

    /**
     * Returns an instance of {@code SEEDSecretKey} associated with the specified session and object handle.
     *
     * @param session
     *            the PKCS#11 session to associate with the secret key
     * @param objectHandle
     *            the handle identifying the secret key object within the session
     * @return a new {@code SEEDSecretKey} instance
     * @throws TokenException
     *             if an error occurs while retrieving the secret key
     */
    public static Object getInstance(final Session session, final long objectHandle) throws TokenException {
        return new SEEDSecretKey(session, objectHandle);
    }

    /**
     * Inserts the value of the given {@code SEEDSecretKey} object into its attribute table
     * under the {@link Attribute#VALUE} key.
     *
     * @param object
     *            the {@code SEEDSecretKey} instance whose value is to be added to its attribute table
     * @throws NullPointerException
     *             if the provided {@code object} is {@code null}
     */
    @SuppressWarnings("unchecked")
    protected static void putAttributesInTable(final SEEDSecretKey object) {
        if (object == null) {
            throw new NullPointerException("Argument \"object\" must not be null.");
        }

        object.attributeTable_.put(Attribute.VALUE, object.value_);
    }

    /**
     * Allocates and initializes the attributes for this object.
     * <p>
     * This method overrides the superclass implementation to allocate
     * a {@link ByteArrayAttribute} for the value attribute and adds
     * all attributes to the internal attribute table.
     */
    @Override
    protected void allocateAttributes() {
        super.allocateAttributes();

        value_ = new ByteArrayAttribute(Attribute.VALUE);

        putAttributesInTable(this);
    }

    /**
     * Creates and returns a deep copy of this {@code SEEDSecretKey} object.
     * <p>
     * This method overrides the {@code clone()} method to ensure that the
     * {@code value_} attribute is also deeply cloned, and that all attributes
     * are properly put into the new attribute table of the cloned object.
     * 
     * @return a deep copy of this {@code SEEDSecretKey} instance
     */
    @Override
    public java.lang.Object clone() {
        SEEDSecretKey clone = (SEEDSecretKey) super.clone();

        clone.value_ = (ByteArrayAttribute) this.value_.clone();

        putAttributesInTable(clone); // put all cloned attributes into the new table

        return clone;
    }

    /**
     * Compares this {@code SEEDSecretKey} object to the specified object for equality.
     * Returns {@code true} if the specified object is also a {@code SEEDSecretKey},
     * and both the superclass's equality and the {@code value_} fields are equal.
     *
     * @param otherObject
     *            the object to compare with this {@code SEEDSecretKey}
     * @return {@code true} if the objects are considered equal; {@code false} otherwise
     */
    @Override
    public boolean equals(final java.lang.Object otherObject) {
        boolean equal = false;

        if (otherObject instanceof SEEDSecretKey) {
            SEEDSecretKey other = (SEEDSecretKey) otherObject;
            equal = (this == other) || (super.equals(other) && this.value_.equals(other.value_));
        }

        return equal;
    }

    /**
     * Returns the value of this secret key as a {@link ByteArrayAttribute}.
     *
     * @return the {@code ByteArrayAttribute} representing the value of the secret key
     */
    @Override
    public ByteArrayAttribute getValue() {
        return value_;
    }

    /**
     * Returns a string representation of this object, including the superclass's string
     * representation and the hexadecimal value of the key.
     *
     * @return a formatted string containing the superclass's string, a newline, an indent,
     *         and the hexadecimal value of the key.
     */
    @Override
    public String toString() {
        StringBuffer buffer = new StringBuffer(1024);

        buffer.append(super.toString());

        buffer.append(Constants.NEWLINE);
        buffer.append(Constants.INDENT);
        buffer.append("Value (hex): ");
        buffer.append(value_.toString());

        return buffer.toString();
    }
}
