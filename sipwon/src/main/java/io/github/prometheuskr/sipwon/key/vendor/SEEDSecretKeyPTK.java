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

public class SEEDSecretKeyPTK extends GenericSecretKey {
    
    private final VendorDefinedKeyBuilder builder = (s, h) -> {
        try {
            return SEEDSecretKeyPTK.getInstance(s, h);
        } catch (TokenException e) {
            throw new PKCS11Exception(0x88000002l);
        }
    };

    protected ByteArrayAttribute value_;

    public SEEDSecretKeyPTK() {
        super();
        keyType_.setLongValue(HsmVendorKeyType.SEED_PTK.getKeyType());
        vendorKeyBuilder_ = builder;
    }

    protected SEEDSecretKeyPTK(final Session session, final long objectHandle) throws TokenException {
        super(session, objectHandle);
        keyType_.setLongValue(HsmVendorKeyType.SEED_PTK.getKeyType());
        vendorKeyBuilder_ = builder;
    }

    public static Object getInstance(final Session session, final long objectHandle) throws TokenException {
        return new SEEDSecretKeyPTK(session, objectHandle);
    }

    @SuppressWarnings("unchecked")
    protected static void putAttributesInTable(final SEEDSecretKeyPTK object) {
        if (object == null) {
            throw new NullPointerException("Argument \"object\" must not be null.");
        }

        object.attributeTable_.put(Attribute.VALUE, object.value_);
    }

    @Override
    protected void allocateAttributes() {
        super.allocateAttributes();

        value_ = new ByteArrayAttribute(Attribute.VALUE);

        putAttributesInTable(this);
    }

    @Override
    public java.lang.Object clone() {
        SEEDSecretKeyPTK clone = (SEEDSecretKeyPTK) super.clone();

        clone.value_ = (ByteArrayAttribute) this.value_.clone();

        putAttributesInTable(clone); // put all cloned attributes into the new table

        return clone;
    }

    @Override
    public boolean equals(final java.lang.Object otherObject) {
        boolean equal = false;

        if (otherObject instanceof SEEDSecretKeyPTK) {
            SEEDSecretKeyPTK other = (SEEDSecretKeyPTK) otherObject;
            equal = (this == other) || (super.equals(other) && this.value_.equals(other.value_));
        }

        return equal;
    }

    @Override
    public ByteArrayAttribute getValue() {
        return value_;
    }

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
