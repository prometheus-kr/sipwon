package io.github.prometheuskr.sipwon;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import iaik.pkcs.pkcs11.InitializeArgs;
import iaik.pkcs.pkcs11.MutexHandler;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

class ModuleTest {
    private iaik.pkcs.pkcs11.Module getInitializedModule(String pkcs11LibraryPath) throws Exception {
        iaik.pkcs.pkcs11.Module module = iaik.pkcs.pkcs11.Module.getInstance(pkcs11LibraryPath);
        InitializeArgs initArgs = new InitializeArgs() {
            @Override
            public MutexHandler getMutexHandler() {
                return null;
            }

            @Override
            public Object getReserved() {
                return null;
            }

            @Override
            public boolean isLibraryCantCreateOsThreads() {
                return false;
            }

            @Override
            public boolean isOsLockingOk() {
                return true;
            }
        };
        runWithAllowedError(() -> module.initialize(initArgs), PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED);
        return module;
    }

    @Test
    void testHsmInitialize() {
        try {
            String pkcs11LibraryPath = "cryptoki.dll";
            iaik.pkcs.pkcs11.Module module = getInitializedModule(pkcs11LibraryPath);
            assertThat(module).isNotNull();
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(false).isTrue();
        }
    }

    @Test
    void testHsmOpenSession() {
        try {
            String pkcs11LibraryPath = "cryptoki.dll";
            iaik.pkcs.pkcs11.Module module = getInitializedModule(pkcs11LibraryPath);
            iaik.pkcs.pkcs11.Slot[] slots = module.getSlotList(true);
            assertThat(slots).isNotEmpty();
            iaik.pkcs.pkcs11.Slot slot = slots[0];
            iaik.pkcs.pkcs11.Session session = slot.getToken().openSession(Token.SessionType.SERIAL_SESSION,
                    Token.SessionReadWriteBehavior.RO_SESSION, null, null);
            assertThat(session).isNotNull();
            session.closeSession();
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(false).isTrue();
        }
    }

    @Test
    void testFindKeyByLabel() throws Exception {
        String pkcs11LibraryPath = "cryptoki.dll";
        iaik.pkcs.pkcs11.Module module = getInitializedModule(pkcs11LibraryPath);
        iaik.pkcs.pkcs11.Slot[] slots = module.getSlotList(true);
        assertThat(slots).isNotEmpty();
        iaik.pkcs.pkcs11.Slot slot = slots[0];
        iaik.pkcs.pkcs11.Session session = slot.getToken().openSession(Token.SessionType.SERIAL_SESSION,
                Token.SessionReadWriteBehavior.RO_SESSION, null, null);

        session.login(true, "1111".toCharArray());

        // label로 key 찾기
        String keyLabel = "0238CPBK01FF";
        iaik.pkcs.pkcs11.objects.Key template = new iaik.pkcs.pkcs11.objects.Key();
        session.findObjectsInit(template);
        iaik.pkcs.pkcs11.objects.Key foundKey = null;
        while (true) {
            iaik.pkcs.pkcs11.objects.Object[] keys = (iaik.pkcs.pkcs11.objects.Object[]) session.findObjects(1);
            if (keys == null || keys.length == 0) {
                break;
            }
            iaik.pkcs.pkcs11.objects.Key key = (iaik.pkcs.pkcs11.objects.Key) keys[0];
            if (key.getLabel().toString().equals(keyLabel)) {
                foundKey = key;
                break;
            }
        }
        session.findObjectsFinal();
        assertThat(foundKey).isNotNull();

        session.closeSession();
    }

    @FunctionalInterface
    interface AllowableErrorRunnable {
        void run() throws Exception;
    }

    void runWithAllowedError(AllowableErrorRunnable runnable, long... allowedErrorCodes) throws Exception {
        try {
            runnable.run();
        } catch (PKCS11Exception e) {
            if (!Arrays.stream(allowedErrorCodes).anyMatch(code -> e.getErrorCode() == code)) {
                throw e;
            }
            // 허용된 에러는 무시
        }
    }

    @Test
    void testMultipleInitializeCalls() throws Exception {
        String pkcs11LibraryPath = "cryptoki.dll";
        getInitializedModule(pkcs11LibraryPath);
        // 10번 반복 initialize 호출 (CKR_CRYPTOKI_ALREADY_INITIALIZED 예외만 허용)
        for (int i = 0; i < 10; i++) {
            runWithAllowedError(() -> getInitializedModule(pkcs11LibraryPath),
                    PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED);
        }
    }

    @Test
    void testMultipleOpenSessionCalls() throws Exception {
        String pkcs11LibraryPath = "cryptoki.dll";
        iaik.pkcs.pkcs11.Module module = getInitializedModule(pkcs11LibraryPath);
        iaik.pkcs.pkcs11.Slot[] slots = module.getSlotList(true);
        assertThat(slots).isNotEmpty();
        iaik.pkcs.pkcs11.Slot slot = slots[0];
        // 10번 반복 openSession 호출 (예외 발생 시 허용된 에러코드만 무시)
        for (int i = 0; i < 10; i++) {
            runWithAllowedError(() -> {
                iaik.pkcs.pkcs11.Session session = slot.getToken().openSession(
                        Token.SessionType.SERIAL_SESSION,
                        Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                assertThat(session).isNotNull();
                session.closeSession();
            }, PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED, PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN,
                    PKCS11Constants.CKR_PIN_INCORRECT);
        }
    }

    @Test
    void testMultipleOpenSessionAndLoginCalls() throws Exception {
        String pkcs11LibraryPath = "cryptoki.dll";
        iaik.pkcs.pkcs11.Module module = getInitializedModule(pkcs11LibraryPath);
        iaik.pkcs.pkcs11.Slot[] slots = module.getSlotList(true);
        assertThat(slots).isNotEmpty();
        iaik.pkcs.pkcs11.Slot slot = slots[0];
        // 10번 반복 openSession + login 호출 (예외 발생 시 허용된 에러코드만 무시)
        for (int i = 0; i < 10; i++) {
            runWithAllowedError(() -> {
                iaik.pkcs.pkcs11.Session session = slot.getToken().openSession(
                        Token.SessionType.SERIAL_SESSION,
                        Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                assertThat(session).isNotNull();
                session.login(true, "1111".toCharArray());
                session.logout();
                session.closeSession();
            }, PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED, PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN,
                    PKCS11Constants.CKR_PIN_INCORRECT);
        }
    }

    @Test
    void testConcurrentOpenSessionAndLogin() throws Exception {
        String pkcs11LibraryPath = "cryptoki.dll";
        iaik.pkcs.pkcs11.Module module = getInitializedModule(pkcs11LibraryPath);
        iaik.pkcs.pkcs11.Slot[] slots = module.getSlotList(true);
        assertThat(slots).isNotEmpty();
        iaik.pkcs.pkcs11.Slot slot = slots[0];
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        Exception[] exceptions = new Exception[threadCount];
        for (int i = 0; i < threadCount; i++) {
            final int idx = i;
            threads[i] = new Thread(() -> {
                try {
                    runWithAllowedError(() -> {
                        iaik.pkcs.pkcs11.Session session = slot.getToken().openSession(
                                Token.SessionType.SERIAL_SESSION,
                                Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                        assertThat(session).isNotNull();
                        session.login(true, "1111".toCharArray());
                        doProcess();
                        session.closeSession();
                    }, PKCS11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED, PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN,
                            PKCS11Constants.CKR_PIN_INCORRECT);
                } catch (Exception e) {
                    exceptions[idx] = e;
                }
            });
            threads[i].start();
        }
        for (Thread t : threads) {
            t.join();
        }
        for (Exception e : exceptions) {
            if (e != null)
                throw e;
        }
    }

    private void doProcess() {
        try {
            System.out.println("Processing in thread1: " + Thread.currentThread().getName());
            Thread.sleep(1000);
            System.out.println("Processing in thread2: " + Thread.currentThread().getName());
        } catch (InterruptedException e) {
            e.printStackTrace();
        } // 실제 처리 로직을 여기에 구현
    }

    @Test
    void testReadAllSlotsInfo() throws Exception {
        String pkcs11LibraryPath = "cryptoki.dll";
        iaik.pkcs.pkcs11.Module module = getInitializedModule(pkcs11LibraryPath);
        iaik.pkcs.pkcs11.Slot[] slots = module.getSlotList(false); // false: 모든 슬롯(토큰 없음 포함)
        assertThat(slots).isNotNull();
        System.out.println("Slot count: " + slots.length);
        for (int i = 0; i < slots.length; i++) {
            iaik.pkcs.pkcs11.Slot slot = slots[i];
            iaik.pkcs.pkcs11.SlotInfo slotInfo = slot.getSlotInfo();
            System.out.printf("Slot[%d]: id=%d, description='%s', manufacturer='%s', tokenPresent=%s\n",
                    i, slot.getSlotID(), slotInfo.getSlotDescription().trim(), slotInfo.getManufacturerID().trim(),
                    slotInfo.isTokenPresent());
            if (slotInfo.isTokenPresent()) {
                iaik.pkcs.pkcs11.TokenInfo tokenInfo = slot.getToken().getTokenInfo();
                System.out.printf("  Token: label='%s', manufacturer='%s', model='%s', serial='%s'\n",
                        tokenInfo.getLabel().trim(), tokenInfo.getManufacturerID().trim(), tokenInfo.getModel().trim(),
                        tokenInfo.getSerialNumber().trim());

                Stream.of(slot.getToken().getMechanismList()).forEach(mechanism -> {
                    System.out.printf("  Mechanism: %s, %s\n", mechanism.getName(),
                            mechanism.getMechanismCode());
                });
            }
        }
    }
}
