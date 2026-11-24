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

    it('DumpStackExplicitFalse', 0, async function (done) {
        console.info('DumpStackExplicitFalse');
        currentStoreId = 'dump_stack_false';
        const options = Object.assign({}, baseOptions, { dumpStackOnFileDeletion: false });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('DumpStackExplicitFalse getKVStore success');
        } catch (e) {
            console.error('DumpStackExplicitFalse fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

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
})
