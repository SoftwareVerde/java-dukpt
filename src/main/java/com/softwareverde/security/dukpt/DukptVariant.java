package com.softwareverde.security.dukpt;

/**
 * <p>Provides a more object-oriented method for derived DUKPT keys, mimicking the public interface of {@link Dukpt} and
 * allowing the internal masks to be specific within the object.
 *
 * <p>The constructors to this object require a key register bitmask (in standard implementations this should be {@link Dukpt#KEY_REGISTER_BITMASK})
 * and the data variant bitmask which may vary depending on the specific key derivation desired.  See <code>{@link Dukpt}.*_VARIANT_BITMASK</code>
 * constants for standard values.
 *
 * @see Dukpt
 */
public class DukptVariant {
    private BitSet _keyRegisterBitmask;
    private BitSet _dataVariantBitmask;

    /**
     * <p>Creates a standard DUKPT variant object with the PIN variant bitmask.
     */
    public DukptVariant() {
        this(Dukpt.KEY_REGISTER_BITMASK, Dukpt.PIN_VARIANT_BITMASK);
    }

    /**
     * <p>Creates a DUKPT variant object with the provided key register bitmask (typically {@link Dukpt#KEY_REGISTER_BITMASK})
     * and data variant bitmask, depending on the type of key derivation desired.
     *
     * @param keyRegisterBitmaskHex
     * @param dataVariantBitmaskHex
     */
    public DukptVariant(final String keyRegisterBitmaskHex, final String dataVariantBitmaskHex) {
        this(Dukpt.toByteArray(keyRegisterBitmaskHex), Dukpt.toByteArray(dataVariantBitmaskHex));
    }

    /**
     * <p>Creates a DUKPT variant object with the provided key register bitmask (typically {@link Dukpt#KEY_REGISTER_BITMASK})
     * and data variant bitmask, depending on the type of key derivation desired.
     *
     * @param keyRegisterBitmask
     * @param dataVariantBitmask
     */
    public DukptVariant(final byte[] keyRegisterBitmask, final byte[] dataVariantBitmask) {
        this(Dukpt.toBitSet(keyRegisterBitmask), Dukpt.toBitSet(dataVariantBitmask));
    }

    /**
     * <p>Creates a DUKPT variant object with the provided key register bitmask (typically {@link Dukpt#KEY_REGISTER_BITMASK})
     * and data variant bitmask, depending on the type of key derivation desired.
     *
     * @param keyRegisterBitmask
     * @param dataVariantBitmask
     */
    public DukptVariant(final BitSet keyRegisterBitmask, final BitSet dataVariantBitmask) {
        this._keyRegisterBitmask = keyRegisterBitmask;
        this._dataVariantBitmask = dataVariantBitmask;
    }

    /**
     * <p>Computes a DUKPT (Derived Unique Key-Per-Transaction).
     *
     * @see Dukpt#computeKey(byte[], byte[])
     * @param baseDerivationKey
     * @param keySerialNumber
     * @return
     * @throws Exception
     */
    public byte[] computeKey(byte[] baseDerivationKey, byte[] keySerialNumber) throws Exception {
        return Dukpt.computeKey(baseDerivationKey, keySerialNumber, _keyRegisterBitmask, _dataVariantBitmask);
    }

    /**
     * <p>Computes the Initial PIN Encryption Key (Sometimes referred to as
     * the Initial PIN Entry Device Key).
     *
     * @see Dukpt#getIpek(BitSet, BitSet)
     * @param key
     * @param ksn
     * @return
     * @throws Exception
     */
    public BitSet getIpek(BitSet key, BitSet ksn) throws Exception {
        return Dukpt.getIpek(key, ksn, _keyRegisterBitmask);
    }

    /**
     * <p>Converts the provided derived key into a "data key".</p>
     *
     * @see Dukpt#toDataKey(byte[])
     * @param derivedKey
     * @return
     * @throws Exception
     */
    public byte[] toDataKey(byte[] derivedKey) throws Exception {
        return Dukpt.toDataKey(derivedKey);
    }
}
