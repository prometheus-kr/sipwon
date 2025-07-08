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
 * Represents a vendor-defined SEED secret key (PTK) for use with PKCS#11 tokens.
 * <p>
 * This class extends {@link GenericSecretKey} and provides specific handling for SEED PTK keys,
 * including attribute allocation, cloning, and equality checks. It also integrates with a vendor-defined
 * key builder for instantiation from a session and object handle.
 * <p>
 * Key features:
 * <ul>
 * <li>Stores the key value as a {@link ByteArrayAttribute}.</li>
 * <li>Supports cloning and deep copy of attributes.</li>
 * <li>Overrides equality and string representation methods for proper comparison and debugging.</li>
 * <li>Handles vendor-specific key type and builder logic.</li>
 * </ul>
 * <p>
 * Usage example:
 * 
 * <pre>
 * SEEDSecretKeyPTK key = new SEEDSecretKeyPTK();
 * // Set attributes, use with PKCS#11 session, etc.
 * </pre>
 * 
 * @see GenericSecretKey
 * @see ByteArrayAttribute
 * @see HsmVendorKeyType
 */
public class SEEDSecretKeyPTK extends GenericSecretKey {

    /**
     * A {@link VendorDefinedKeyBuilder} implementation that creates a {@link SEEDSecretKeyPTK}
     * instance using the provided session and handle. If a {@link TokenException} occurs during
     * instantiation, it throws a {@link PKCS11Exception} with a specific error code (0x88000002L).
     */
    private final VendorDefinedKeyBuilder builder = (s, h) -> {
        try {
            return SEEDSecretKeyPTK.getInstance(s, h);
        } catch (TokenException e) {
            throw new PKCS11Exception(0x88000002l);
        }
    };

    /**
     * The attribute that holds the value of the secret key as a byte array.
     * This is typically used to store the actual key material for cryptographic operations.
     */
    protected ByteArrayAttribute value_;

    /**
     * Default constructor for the SEEDSecretKeyPTK class.
     * <p>
     * Initializes the SEED PTK (Primary Traffic Key) secret key by setting the key type
     * to the SEED PTK vendor-specific value and assigning the vendor key builder.
     */
    public SEEDSecretKeyPTK() {
        super();
        keyType_.setLongValue(HsmVendorKeyType.SEED_PTK.getKeyType());
        vendorKeyBuilder_ = builder;
    }

    /**
     * Constructs a SEEDSecretKeyPTK object associated with the given session and object handle.
     *
     * @param session
     *            the session associated with this key
     * @param objectHandle
     *            the handle identifying the key object in the HSM
     * @throws TokenException
     *             if an error occurs during key initialization
     */
    protected SEEDSecretKeyPTK(final Session session, final long objectHandle) throws TokenException {
        super(session, objectHandle);
        keyType_.setLongValue(HsmVendorKeyType.SEED_PTK.getKeyType());
        vendorKeyBuilder_ = builder;
    }

    /**
     * Creates and returns a new instance of {@code SEEDSecretKeyPTK} associated with the specified session and object
     * handle.
     *
     * @param session
     *            the PKCS#11 session to associate with the secret key object
     * @param objectHandle
     *            the handle identifying the secret key object within the session
     * @return a new {@code SEEDSecretKeyPTK} instance
     * @throws TokenException
     *             if an error occurs while accessing the token or creating the object
     */
    public static Object getInstance(final Session session, final long objectHandle) throws TokenException {
        return new SEEDSecretKeyPTK(session, objectHandle);
    }

    /**
     * Inserts the value of the {@code value_} field from the specified {@link SEEDSecretKeyPTK} object
     * into its {@code attributeTable_} using {@link Attribute#VALUE} as the key.
     *
     * @param object
     *            the {@link SEEDSecretKeyPTK} instance whose attribute table will be updated
     * @throws NullPointerException
     *             if the {@code object} parameter is {@code null}
     */
    @SuppressWarnings("unchecked")
    protected static void putAttributesInTable(final SEEDSecretKeyPTK object) {
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
     * Creates and returns a deep copy of this {@code SEEDSecretKeyPTK} object.
     * <p>
     * This method overrides the {@code clone()} method to ensure that the
     * {@code value_} attribute is also deeply cloned, preventing shared references
     * between the original and the cloned object. After cloning, all attributes
     * are registered in the new object's attribute table.
     * 
     * @return a deep copy of this {@code SEEDSecretKeyPTK} instance
     * @throws CloneNotSupportedException
     *             if the object's class does not support the {@code Cloneable} interface
     */
    @Override
    public java.lang.Object clone() {
        SEEDSecretKeyPTK clone = (SEEDSecretKeyPTK) super.clone();

        clone.value_ = (ByteArrayAttribute) this.value_.clone();

        putAttributesInTable(clone); // put all cloned attributes into the new table

        return clone;
    }

    /**
     * Indicates whether some other object is "equal to" this one.
     * <p>
     * This method overrides the {@code equals} method to provide equality comparison
     * specific to {@code SEEDSecretKeyPTK} objects. Two {@code SEEDSecretKeyPTK} instances
     * are considered equal if they are the same instance, or if the superclass's
     * {@code equals} method returns {@code true} and their {@code value_} fields are equal.
     * 
     * @param otherObject
     *            the reference object with which to compare
     * @return {@code true} if this object is the same as the {@code otherObject}
     *         argument or if both are {@code SEEDSecretKeyPTK} instances with equal values;
     *         {@code false} otherwise
     */
    @Override
    public boolean equals(final java.lang.Object otherObject) {
        boolean equal = false;

        if (otherObject instanceof SEEDSecretKeyPTK) {
            SEEDSecretKeyPTK other = (SEEDSecretKeyPTK) otherObject;
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
     * @return a formatted string containing the superclass's toString output and the
     *         hexadecimal representation of the key value.
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
