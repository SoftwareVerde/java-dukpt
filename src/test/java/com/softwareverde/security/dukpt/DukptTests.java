package com.softwareverde.security.dukpt;

import org.junit.Assert;
import org.junit.Test;

public class DukptTests {
    @Test
    public void testDecryptValidData() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String dataHexString = "C25C1D1197D31CAA87285D59A892047426D9182EC11353C051ADD6D0F072A6CB3436560B3071FC1FD11D9F7E74886742D9BEE0CFD1EA1064C213BB55278B2F12";
        String expectedValue = "%B5452300551227189^HOGAN/PAUL      ^08043210000000725000000?\0\0\0\0";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);
        byte[] data = Dukpt.toByteArray(dataHexString);

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        data = Dukpt.decryptTripleDes(key, data);
        String dataOutput = new String(data, "UTF-8");

        // Assert
        Assert.assertEquals(expectedValue, dataOutput);
    }

    @Test
    public void testEncrypt() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";
        String payloadString = "Mary had a little lamb.";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        byte[] encryptedPayload;
        byte[] decryptedPayload;

        // Action
        byte[] key = Dukpt.computeKey(bdk, ksn);
        encryptedPayload = Dukpt.encryptTripleDes(key, payloadString.getBytes("UTF-8"), true);
        decryptedPayload = Dukpt.decryptTripleDes(key, encryptedPayload);

        String dataOutput = new String(decryptedPayload, "UTF-8").trim();

        // Assert
        Assert.assertEquals(payloadString, dataOutput);
    }

    @Test
    public void testGetIpek() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "629949012C0000000003";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        // Action
        final DukptVariant dukptVariant = new DukptVariant();
        BitSet ipek = dukptVariant.getIpek(Dukpt.toBitSet(bdk), Dukpt.toBitSet(ksn));

        // Assert
        Assert.assertEquals("D2943CCF80F42E88E23C12D1162FD547", Dukpt.toHex(Dukpt.toByteArray(ipek)));
    }

    @Test
    public void testToDataKey() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210E00008";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        // Action
        final DukptVariant dukptVariant = new DukptVariant(Dukpt.KEY_REGISTER_BITMASK, Dukpt.DATA_VARIANT_BITMASK);
        byte[] derivedKey = dukptVariant.computeKey(bdk, ksn);
        byte[] dataKey = dukptVariant.toDataKey(derivedKey);

        // Assert
        Assert.assertEquals("C39B2778B058AC376FB18DC906F75CBA", Dukpt.toHex(dataKey));
    }

    @Test
    public void testTransactionCounterMsb() throws Exception {
        // Setup
        String bdkHexString = "0123456789ABCDEFFEDCBA9876543210"; // ANSI Test Key
        String ksnHexString = "FFFF9876543210F00000";

        byte[] bdk = Dukpt.toByteArray(bdkHexString);
        byte[] ksn = Dukpt.toByteArray(ksnHexString);

        // Action
        final DukptVariant dukptVariant = new DukptVariant(Dukpt.KEY_REGISTER_BITMASK, Dukpt.PIN_VARIANT_BITMASK);
        byte[] derivedKey = dukptVariant.computeKey(bdk, ksn);

        // Assert
        Assert.assertEquals("AA4D58DB653EC7B548C75F2F047DD24A", Dukpt.toHex(derivedKey));
    }
}
