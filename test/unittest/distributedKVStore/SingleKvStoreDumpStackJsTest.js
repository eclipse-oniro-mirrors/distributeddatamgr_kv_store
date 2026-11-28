/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import factory from '@ohos.data.distributedKVStore'
import abilityFeatureAbility from '@ohos.ability.featureAbility'

var context = abilityFeatureAbility.getContext();
const TEST_BUNDLE_NAME = 'com.example.myapplication';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
const VALUE_TEST_STRING_ELEMENT = 'value-string-001';
var kvManager = null;
var kvStore = null;
var currentStoreId = null;

describe('SingleKvStoreDumpStackTest', function () {
    const config = {
        bundleName: TEST_BUNDLE_NAME,
        context: context
    }

    const baseOptions = {
        createIfMissing: true,
        encrypt: false,
        backup: true,
        autoSync: false,
        kvStoreType: factory.KVStoreType.SINGLE_VERSION,
        schema: '',
        securityLevel: factory.SecurityLevel.S2,
    }

    beforeAll(async function (done) {
        console.info('SingleKvStoreDumpStackTest beforeAll');
        kvManager = factory.createKVManager(config);
        done();
    })

    afterAll(async function (done) {
        console.info('SingleKvStoreDumpStackTest afterAll');
        kvManager = null;
        done();
    })

    afterEach(async function (done) {
        console.info('SingleKvStoreDumpStackTest afterEach storeId=' + currentStoreId);
        if (kvStore != null) {
            try {
                await kvManager.closeKVStore(TEST_BUNDLE_NAME, currentStoreId);
                await kvManager.deleteKVStore(TEST_BUNDLE_NAME, currentStoreId);
            } catch (e) {
                console.error('afterEach cleanup error: ' + `, error code is ${e.code}, message is ${e.message}`);
            }
            kvStore = null;
        }
        currentStoreId = null;
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0100
     * @tc.name DumpStackDefaultDisabled
     * @tc.desc Test getKVStore without dumpStackOnFileDeletion (default false) and Put/Get
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackDefaultDisabled', 0, async function (done) {
        console.info('DumpStackDefaultDisabled');
        currentStoreId = 'dump_stack_default';
        const options = Object.assign({}, baseOptions);
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            console.info('DumpStackDefaultDisabled Put/Get success');
        } catch (e) {
            console.error('DumpStackDefaultDisabled fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0200
     * @tc.name DumpStackExplicitFalse
     * @tc.desc Test getKVStore with dumpStackOnFileDeletion = false and Put/Get
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackExplicitFalse', 0, async function (done) {
        console.info('DumpStackExplicitFalse');
        currentStoreId = 'dump_stack_false';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: false });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            console.info('DumpStackExplicitFalse Put/Get success');
        } catch (e) {
            console.error('DumpStackExplicitFalse fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0300
     * @tc.name DumpStackEnabledOpenSuccess
     * @tc.desc Test getKVStore with dumpStackOnFileDeletion = true and Put/Get
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackEnabledOpenSuccess', 0, async function (done) {
        console.info('DumpStackEnabledOpenSuccess');
        currentStoreId = 'dump_stack_enabled';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: true });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            console.info('DumpStackEnabledOpenSuccess Put/Get success');
        } catch (e) {
            console.error('DumpStackEnabledOpenSuccess fail: ' +
                `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0400
     * @tc.name DumpStackUndefined
     * @tc.desc Test getKVStore with dumpStackOnFileDeletion = undefined (fallback to default) and Put/Get
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackUndefined', 0, async function (done) {
        console.info('DumpStackUndefined');
        currentStoreId = 'dump_stack_undefined';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: undefined });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            console.info('DumpStackUndefined Put/Get success');
        } catch (e) {
            console.error('DumpStackUndefined fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0500
     * @tc.name DumpStackNull
     * @tc.desc Test getKVStore with dumpStackOnFileDeletion = null (fallback to default) and Put/Get
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackNull', 0, async function (done) {
        console.info('DumpStackNull');
        currentStoreId = 'dump_stack_null';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: null });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            console.info('DumpStackNull Put/Get success');
        } catch (e) {
            console.error('DumpStackNull fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0600
     * @tc.name DumpStackInvalidTypeRejected
     * @tc.desc Test getKVStore rejects non-boolean string dumpStackOnFileDeletion with error code 401
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackInvalidTypeRejected', 0, async function (done) {
        console.info('DumpStackInvalidTypeRejected');
        currentStoreId = 'dump_stack_invalid_type';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: 'notBoolean' });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            console.error('DumpStackInvalidTypeRejected getKVStore should not succeed');
            expect(null).assertFail();
        } catch (e) {
            console.error('DumpStackInvalidTypeRejected fail: ' +
                `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0700
     * @tc.name DumpStackInvalidNumberTypeRejected
     * @tc.desc Test getKVStore rejects non-boolean number dumpStackOnFileDeletion with error code 401
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackInvalidNumberTypeRejected', 0, async function (done) {
        console.info('DumpStackInvalidNumberTypeRejected');
        currentStoreId = 'dump_stack_invalid_number';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: 1 });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            console.error('DumpStackInvalidNumberTypeRejected getKVStore should not succeed');
            expect(null).assertFail();
        } catch (e) {
            console.error('DumpStackInvalidNumberTypeRejected fail: ' +
                `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0800
     * @tc.name DumpStackCallbackEnabled
     * @tc.desc Test getKVStore callback overload with dumpStackOnFileDeletion = true and Put/Get
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackCallbackEnabled', 0, function (done) {
        console.info('DumpStackCallbackEnabled');
        currentStoreId = 'dump_stack_callback';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: true });
        let finished = false;
        const finish = () => {
            if (!finished) {
                finished = true;
                done();
            }
        };
        try {
            kvManager.getKVStore(currentStoreId, options, async function (err, store) {
                if (err != undefined) {
                    console.error('DumpStackCallbackEnabled callback fail: ' +
                        `, error code is ${err.code}, message is ${err.message}`);
                    expect(null).assertFail();
                    finish();
                    return;
                }
                kvStore = store;
                try {
                    expect(kvStore != null).assertTrue();
                    await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
                    const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
                    expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
                    console.info('DumpStackCallbackEnabled Put/Get success');
                } catch (e) {
                    console.error('DumpStackCallbackEnabled Put/Get fail: ' +
                        `, error code is ${e.code}, message is ${e.message}`);
                    expect(null).assertFail();
                }
                finish();
            });
        } catch (e) {
            console.error('DumpStackCallbackEnabled fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
            finish();
        }
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_0900
     * @tc.name DumpStackToggleReopen
     * @tc.desc Test reopening store with changed dumpStackOnFileDeletion succeeds (not persisted to metadata)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackToggleReopen', 0, async function (done) {
        console.info('DumpStackToggleReopen');
        currentStoreId = 'dump_stack_toggle_reopen';
        const enabledOptions = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: true });
        const disabledOptions = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: false });
        const omittedOptions = Object.assign({}, baseOptions);
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, enabledOptions);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            await kvManager.closeKVStore(TEST_BUNDLE_NAME, currentStoreId);
            kvStore = null;

            kvStore = await kvManager.getKVStore(currentStoreId, disabledOptions);
            expect(kvStore != null).assertTrue();
            let result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            await kvManager.closeKVStore(TEST_BUNDLE_NAME, currentStoreId);
            kvStore = null;

            kvStore = await kvManager.getKVStore(currentStoreId, omittedOptions);
            expect(kvStore != null).assertTrue();
            result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            console.info('DumpStackToggleReopen success');
        } catch (e) {
            console.error('DumpStackToggleReopen fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_1000
     * @tc.name DumpStackBackupRestoreDelete
     * @tc.desc Test backup, restore, deleteBackup and deleteKVStore when dumpStackOnFileDeletion is true
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackBackupRestoreDelete', 0, async function (done) {
        console.info('DumpStackBackupRestoreDelete');
        currentStoreId = 'dump_stack_backup_restore';
        const backupFile = 'dump_stack_backup_001';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: true });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            await kvStore.backup(backupFile);
            await kvStore.put(KEY_TEST_STRING_ELEMENT, 'value-string-modified');
            await kvStore.restore(backupFile);
            const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            const deleteResults = await kvStore.deleteBackup([backupFile]);
            expect(deleteResults != null && deleteResults.length == 1).assertTrue();
            await kvManager.closeKVStore(TEST_BUNDLE_NAME, currentStoreId, options);
            await kvManager.deleteKVStore(TEST_BUNDLE_NAME, currentStoreId, options);
            kvStore = null;
            console.info('DumpStackBackupRestoreDelete success');
        } catch (e) {
            console.error('DumpStackBackupRestoreDelete fail: ' +
                `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_1100
     * @tc.name DumpStackDeviceStoreEnabled
     * @tc.desc Test getKVStore for DEVICE_COLLABORATION with dumpStackOnFileDeletion = true
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackDeviceStoreEnabled', 0, async function (done) {
        console.info('DumpStackDeviceStoreEnabled');
        currentStoreId = 'dump_stack_device_enabled';
        const options = Object.assign({}, baseOptions, {
            kvStoreType: factory.KVStoreType.DEVICE_COLLABORATION,
            dumpStackOnFileDeletion: true,
        });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            console.info('DumpStackDeviceStoreEnabled success');
        } catch (e) {
            console.error('DumpStackDeviceStoreEnabled fail: ' +
                `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_1200
     * @tc.name DumpStackInvalidObjectTypeRejected
     * @tc.desc Test getKVStore rejects non-boolean object dumpStackOnFileDeletion with error code 401
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackInvalidObjectTypeRejected', 0, async function (done) {
        console.info('DumpStackInvalidObjectTypeRejected');
        currentStoreId = 'dump_stack_invalid_object';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: {} });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            console.error('DumpStackInvalidObjectTypeRejected getKVStore should not succeed');
            expect(null).assertFail();
        } catch (e) {
            console.error('DumpStackInvalidObjectTypeRejected fail: ' +
                `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.number SUB_DDM_DKV_SINGLEKVSTORE_DUMPSTACK_1300
     * @tc.name DumpStackCustomRootDirEnabled
     * @tc.desc Test getKVStore with rootDir and dumpStackOnFileDeletion = true and Put/Get
     * @tc.type: FUNC
     * @tc.require:
     */
    it('DumpStackCustomRootDirEnabled', 0, async function (done) {
        console.info('DumpStackCustomRootDirEnabled');
        currentStoreId = 'dump_stack_custom_root_dir';
        const options = Object.assign({}, baseOptions, {
            backup: false,
            rootDir: '/data/storage/el2/database/entry',
            dumpStackOnFileDeletion: true,
        });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            await kvManager.closeKVStore(TEST_BUNDLE_NAME, currentStoreId, options);
            await kvManager.deleteKVStore(TEST_BUNDLE_NAME, currentStoreId, options);
            kvStore = null;
            console.info('DumpStackCustomRootDirEnabled success');
        } catch (e) {
            console.error('DumpStackCustomRootDirEnabled fail: ' +
                `, error code is ${e.code}, message is ${e.message}`);
            if (kvStore != null) {
                try {
                    await kvManager.closeKVStore(TEST_BUNDLE_NAME, currentStoreId, options);
                    await kvManager.deleteKVStore(TEST_BUNDLE_NAME, currentStoreId, options);
                } catch (cleanupErr) {
                    console.error('DumpStackCustomRootDirEnabled cleanup fail: ' +
                        `, error code is ${cleanupErr.code}, message is ${cleanupErr.message}`);
                }
                kvStore = null;
            }
            expect(null).assertFail();
        }
        done();
    })
})
