'use strict';

import {createReadStream, createWriteStream, promises as fs} from 'fs';
import {createCipheriv, createDecipheriv} from 'crypto';
import {Readable, promises as stream} from 'stream';
import {spawn} from 'child_process';
import config from 'config';

export type GetDataArgs = {
    path: string;
};

export type SetDataArgs = {
    path: string;
    data: string;
};

export type Storage = {[key: string]: string | Storage};

export const exists = async (path: string) => {
    try {
        await fs.stat(path);
        return true;
    } catch {
        return false;
    }
}

export const getKeystore = () => {
    const {k, iv} = require(config.get('keystore'));
    return {k: Buffer.from(k, 'hex'), iv: Buffer.from(iv, 'hex')};
};

export const readStorage = async () => {
    const {k, iv} = getKeystore();
    const storage = config.get('storage') as string;
    if (!await exists(storage)) {
        return {};
    }
    const data = [] as Buffer[];
    await stream.pipeline([
        createReadStream(storage),
        createDecipheriv(config.get('algorithm'), k, iv)
            .on('data', chunk => data.push(chunk))
    ]);
    return JSON.parse(Buffer.concat(data).toString())
};

export const writeStorage = async (data: Storage) => {
    const {k, iv} = getKeystore();
    const storage = config.get('storage') as string;
    const backup = `${storage}-${Date.now()}`;
    if (await exists(storage)) {
        await fs.copyFile(storage, backup);
    }
    await fs.unlink(storage);
    try {
        await stream.pipeline([
            Readable.from(JSON.stringify(data)),
            createCipheriv(config.get('algorithm'), k, iv),
            createWriteStream(storage, {flags: 'w'})
        ])
        if (await exists(backup)) {
            await fs.rm(backup);
        }
    } catch (e) {
        console.log({e});
        if (await exists(backup)) {
            await fs.copyFile(backup, storage);
        }
        throw e;
    }
};

export const setData = async ({data, path}: SetDataArgs) => {
    if (!path) {
        throw new Error('Storage path is not specified');
    }
    if (!data) {
        throw new Error('Data is not specified');
    }
    const storage = await readStorage() as Storage;
    let keys = path.split('.') as string[];
    let location: string | Storage = storage;
    while (keys.length > 1) {
        const key = keys.shift() as string;
        if (typeof location === 'string') {
            throw new Error(`Unable to write ${key} in a stored data`);
        }
        if (!(key in location)) {
            location[key] = {};
        }
        location = location[key] as string | Storage;
    }
    const key = keys.shift();
    if (!key || typeof location === 'string') {
        throw new Error(`Unable to follow the specified path at ${key}`);
    }
    location[key] = data;
    return writeStorage(storage);
};

export const getData = async ({path}: GetDataArgs) => {
    const storage = await readStorage();
    if (!path) {
        return storage;
    }
    let keys = path.split('.');
    let data = storage;
    while (keys.length) {
        const key = keys.shift();
        if (!key || typeof data === 'string' || !(key in data)) {
            throw new Error(`Unable to follow the specified path at ${key}`);
        }
        data = data[key];
    }
    return data;
};

export const pbcopy = (data: string | Storage) => {
    const proc = spawn('pbcopy');
    proc.stdin.write(typeof data === 'string' ? data : JSON.stringify(data));
    proc.stdin.end();
}

const setCommands = new Set(['-s', 'set', '--set']);
const getCommands = new Set(['-g', 'get', '--get']);

(async () => {
    const [command, path, data] = process.argv.slice(2) as string[];
    try {
        if (getCommands.has(command)) {
            return pbcopy(await getData({path}));
        }
        if (setCommands.has(command)) {
            return await setData({path, data});
        }
        throw new Error(`Unknown command: "${command}"`);
    } catch (e) {
        console.error('Kmaster error:', e);
    }
})();
