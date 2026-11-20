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

describe('SingleKvStoreCheckpointTest', function () {
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
        console.info('SingleKvStoreCheckpointTest beforeAll');
        kvManager = factory.createKVManager(config);
        done();
    })

    afterAll(async function (done) {
        console.info('SingleKvStoreCheckpointTest afterAll');
        kvManager = null;
        done();
    })

    afterEach(async function (done) {
        console.info('SingleKvStoreCheckpointTest afterEach storeId=' + currentStoreId);
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
     * @tc.name CheckpointDefaultNotSet
     * @tc.desc Test getKVStore without walStartCheckpointSize (default 204800 KB)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointDefaultNotSet', 0, async function (done) {
        console.info('CheckpointDefaultNotSet');
        currentStoreId = 'checkpoint_default';
        const options = Object.assign({}, baseOptions);
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('CheckpointDefaultNotSet getKVStore success');
        } catch (e) {
            console.error('CheckpointDefaultNotSet fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.name CheckpointValidValue
     * @tc.desc Test getKVStore with valid walStartCheckpointSize (8192 KB) and Put/Get
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointValidValue', 0, async function (done) {
        console.info('CheckpointValidValue');
        currentStoreId = 'checkpoint_valid';
        const options = Object.assign({}, baseOptions, { walStartCheckpointSize: 8192 });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            await kvStore.put(KEY_TEST_STRING_ELEMENT, VALUE_TEST_STRING_ELEMENT);
            const result = await kvStore.get(KEY_TEST_STRING_ELEMENT);
            expect(result == VALUE_TEST_STRING_ELEMENT).assertTrue();
            console.info('CheckpointValidValue Put/Get success');
        } catch (e) {
            console.error('CheckpointValidValue fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.name CheckpointMinBoundary
     * @tc.desc Test getKVStore with walStartCheckpointSize = 16 (MIN boundary)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointMinBoundary', 0, async function (done) {
        console.info('CheckpointMinBoundary');
        currentStoreId = 'checkpoint_min';
        const options = Object.assign({}, baseOptions, { walStartCheckpointSize: 16 });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('CheckpointMinBoundary getKVStore success');
        } catch (e) {
            console.error('CheckpointMinBoundary fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.name CheckpointMaxBoundary
     * @tc.desc Test getKVStore with walStartCheckpointSize = 524288 (MAX boundary)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointMaxBoundary', 0, async function (done) {
        console.info('CheckpointMaxBoundary');
        currentStoreId = 'checkpoint_max';
        const options = Object.assign({}, baseOptions, { walStartCheckpointSize: 524288 });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('CheckpointMaxBoundary getKVStore success');
        } catch (e) {
            console.error('CheckpointMaxBoundary fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.name CheckpointTooSmall
     * @tc.desc Test getKVStore with walStartCheckpointSize = 0 (below MIN, fallback to default)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointTooSmall', 0, async function (done) {
        console.info('CheckpointTooSmall');
        currentStoreId = 'checkpoint_too_small';
        const options = Object.assign({}, baseOptions, { walStartCheckpointSize: 0 });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('CheckpointTooSmall getKVStore success (fallback to default)');
        } catch (e) {
            console.error('CheckpointTooSmall fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.name CheckpointNegative
     * @tc.desc Test getKVStore with walStartCheckpointSize = -1 (negative, fallback to default)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointNegative', 0, async function (done) {
        console.info('CheckpointNegative');
        currentStoreId = 'checkpoint_negative';
        const options = Object.assign({}, baseOptions, { walStartCheckpointSize: -1 });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('CheckpointNegative getKVStore success (fallback to default)');
        } catch (e) {
            console.error('CheckpointNegative fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.name CheckpointTooLarge
     * @tc.desc Test getKVStore with walStartCheckpointSize = 999999 (above MAX, fallback to default)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointTooLarge', 0, async function (done) {
        console.info('CheckpointTooLarge');
        currentStoreId = 'checkpoint_too_large';
        const options = Object.assign({}, baseOptions, { walStartCheckpointSize: 999999 });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('CheckpointTooLarge getKVStore success (fallback to default)');
        } catch (e) {
            console.error('CheckpointTooLarge fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.name CheckpointNaN
     * @tc.desc Test getKVStore with walStartCheckpointSize = NaN (invalid, fallback to default)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointNaN', 0, async function (done) {
        console.info('CheckpointNaN');
        currentStoreId = 'checkpoint_nan';
        const options = Object.assign({}, baseOptions, { walStartCheckpointSize: NaN });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('CheckpointNaN getKVStore success (fallback to default)');
        } catch (e) {
            console.error('CheckpointNaN fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })

    /**
     * @tc.name CheckpointInfinity
     * @tc.desc Test getKVStore with walStartCheckpointSize = Infinity (invalid, fallback to default)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('CheckpointInfinity', 0, async function (done) {
        console.info('CheckpointInfinity');
        currentStoreId = 'checkpoint_infinity';
        const options = Object.assign({}, baseOptions, { walStartCheckpointSize: Infinity });
        try {
            kvStore = await kvManager.getKVStore(currentStoreId, options);
            expect(kvStore != null).assertTrue();
            console.info('CheckpointInfinity getKVStore success (fallback to default)');
        } catch (e) {
            console.error('CheckpointInfinity fail: ' + `, error code is ${e.code}, message is ${e.message}`);
            expect(null).assertFail();
        }
        done();
    })
})
