import * as openpgp from 'openpgp'
import { randomBytes, createHash } from 'crypto'
import { networkInterfaces } from 'os'
import * as keytar from 'keytar'

const service = require ('../package.json').name

type ResolvedType<T> = T extends PromiseLike<infer U> ? U : T

export async function createKeys ({
    name,
    email: useremail,
    passphrase = undefined,
    numBits = 4096 
}: {
    name: string,
    email: string,
    passphrase: string,
    numBits?: number
}): Promise<ResolvedType<ReturnType<typeof openpgp.generateKey>> & {
    tag: string,
    email: string,
    passphrase: string,
}> {

    const interfaces = networkInterfaces ()
    let tag: string

    for (const name in interfaces) {
        if (name !== 'en0' && name !== 'eth0') continue
        for (const info of interfaces[name]) {
            if (!info.mac) continue
            tag = createHash ('sha256').update (info.mac).digest ('hex')
            break
        }
    }

    if (!tag) {
        throw new Error ('Unable to determine MAC address')
    }

    if (!passphrase) {
        passphrase = randomBytes (256).toString ('base64')
    }

    const email = useremail.split ('@').map ((w, i) => i === 0 ? `${w}+${tag}` : w).join ('@')
    const key = await openpgp.generateKey ({
        userIds: [{ name, email }],
        numBits,
        passphrase
    })

    return { ...key, tag, email, passphrase }
}

export async function revokeKey ({
    publicKeyArmored,
    privateKeyArmored,
    revocationCertificate,
}: ResolvedType<ReturnType<typeof openpgp.generateKey>>): Promise<ResolvedType<ReturnType<typeof openpgp.revokeKey>>> {
    return openpgp.revokeKey ({
        // @ts-ignore: the typings are a bit outdated
        key: (await openpgp.key.readArmored (publicKeyArmored)).keys[0],
        revocationCertificate
    })
}

export function storeKeys ({
    publicKeyArmored,
    privateKeyArmored,
    revocationCertificate,
    account,
}: ResolvedType<ReturnType<typeof openpgp.generateKey>> & {
    account: string
}): ReturnType<typeof keytar.setPassword> {

    const payload = JSON.stringify ({ publicKeyArmored, privateKeyArmored, revocationCertificate })
    return keytar.setPassword (service, account, payload)
}

export function deleteKeys ({ account }: { account: string }): ReturnType<typeof keytar.deletePassword> {
    return keytar.deletePassword (service, account)
}

export async function getKeys ({ account }: { account: string }): Promise<ResolvedType<ReturnType<typeof openpgp.generateKey>>>{

    const keys = await keytar.getPassword (service, account)
    return JSON.parse (keys) as ResolvedType<ReturnType<typeof openpgp.generateKey>>
}
