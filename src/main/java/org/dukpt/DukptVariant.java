package org.dukpt;

    public class DukptVariant {
        private BitSet _keyRegisterBitmask;
        private BitSet _dataVariantBitmask;

        public DukptVariant() {
            this(Dukpt.KEY_REGISTER_BITMASK, Dukpt.PIN_VARIANT_BITMASK);
        }

        public DukptVariant(final String keyRegisterBitmaskHex, final String dataVariantBitmaskHex) {
            this(Dukpt.toByteArray(keyRegisterBitmaskHex), Dukpt.toByteArray(dataVariantBitmaskHex));
        }

        public DukptVariant(final byte[] keyRegisterBitmask, final byte[] dataVariantBitmask) {
            this(Dukpt.toBitSet(keyRegisterBitmask), Dukpt.toBitSet(dataVariantBitmask));
        }

        public DukptVariant(final BitSet keyRegisterBitmask, final BitSet dataVariantBitmask) {
            this._keyRegisterBitmask = keyRegisterBitmask;
            this._dataVariantBitmask = dataVariantBitmask;
        }

        public byte[] computeKey(byte[] baseDerivationKey, byte[] keySerialNumber) throws Exception {
            return Dukpt.computeKey(baseDerivationKey, keySerialNumber, _keyRegisterBitmask, _dataVariantBitmask);
        }

        public BitSet getIpek(BitSet key, BitSet ksn) throws Exception {
            return Dukpt.getIpek(key, ksn, _keyRegisterBitmask);
        }

        public byte[] toDataKey(byte[] derivedKey) throws Exception {
            return Dukpt.toDataKey(derivedKey);
        }
}
