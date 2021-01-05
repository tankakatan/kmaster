import { expect } from 'chai'
import {
    createKeys,
    revokeKey,
    getKeys,
    storeKeys,
    deleteKeys,
} from '../src/scrambler'

describe ('scrambler', function () {

    this.timeout(5000)

    const email = 'test@test.com'

    it ('generates a new keypair', async () => {
        const key = await createKeys ({
            name: 'Test',
            email,
            passphrase: 'Test test test test test test'
        })

        await revokeKey (key)
    })

    it ('stores a key in the keychain', async () => {
        const key = await createKeys ({
            name: 'Test',
            email,
            passphrase: 'Test test test test test test'
        })

        const account = key.email

        await storeKeys ({ ...key, account })
        const keys = await getKeys ({ account })

        expect (keys).to.have.property ('publicKeyArmored', key.publicKeyArmored)
        expect (keys).to.have.property ('privateKeyArmored', key.privateKeyArmored)
        expect (keys).to.have.property ('revocationCertificate', key.revocationCertificate)

        await deleteKeys ({ account })
        await revokeKey (key)
    })
})
