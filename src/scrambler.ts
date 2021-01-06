import * as crypto from 'crypto'
import * as openpgp from 'openpgp'
import { randomBytes, createHash } from 'crypto'
import { networkInterfaces } from 'os'

const { name: service } = require ('../package.json')

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

export function encrypt ({ data, key: password }: { data: string, key: string }): string {
    const iv = crypto.randomBytes (16)
    const key = crypto.createHash ('sha256').update (password).digest ()
    const cipher = crypto.createCipheriv ('aes256', key, iv)
    return iv.toString ('hex') + ':' + (cipher.update (data, 'utf-8', 'hex') + cipher.final ('hex'))
}

export function decrypt ({ data, key: password }: { data: string, key: string }): string {
    const [ivHex, cyphertext] = data.split (':')
    const iv = Buffer.from (ivHex, 'hex')
    const key = crypto.createHash ('sha256').update (password).digest ()
    const decipher = crypto.createDecipheriv ('aes256', key, iv)
    return decipher.update (cyphertext, 'hex', 'utf-8') + decipher.final ('utf-8')
}
