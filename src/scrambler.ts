import * as openpgp from 'openpgp'
import { randomBytes } from 'crypto'
import { networkInterfaces } from 'os'

type ThenArg<T> = T extends PromiseLike<infer U> ? U : T

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
}): Promise<ThenArg<ReturnType<typeof openpgp.generateKey>> & {
    mac: string,
    email: string,
    passphrase: string,
    revoke: () => ReturnType<typeof openpgp.revokeKey>
}> {
    const interfaces = networkInterfaces ()
    let mac: string

    for (const name in interfaces) {
        if (name !== 'en0' && name !== 'eth0') continue
        for (const info of interfaces[name]) {
            if (!info.mac) continue
            mac = info.mac
            break
        }
    }

    if (!mac) {
        throw new Error ('Unable to determine MAC address')
    }

    if (!passphrase) {
        passphrase = randomBytes (256).toString ('base64')
    }

    const email = useremail.split('@').map((w, i) => i === 0 ? `${w}+${mac.replace(/:/g, '_')}` : w).join('@')
    const key = await openpgp.generateKey ({
        userIds: [{ name, email }],
        numBits,
        passphrase
    })

    const revoke = async () => {
        return openpgp.revokeKey ({
            // @ts-ignore
            key: (await openpgp.key.readArmored (key.publicKeyArmored)).keys[0],
            revocationCertificate: key.revocationCertificate
        })
    }

    return Object.assign (key, {mac, email, passphrase, revoke })
}
