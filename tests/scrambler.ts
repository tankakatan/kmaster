import { expect } from 'chai'
import {
    createKeys,
    revokeKey,
    encrypt,
    decrypt
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

        expect (key).to.have.property ('publicKeyArmored', key.publicKeyArmored)
        expect (key).to.have.property ('privateKeyArmored', key.privateKeyArmored)
        expect (key).to.have.property ('revocationCertificate', key.revocationCertificate)

        await revokeKey (key)
    })

    it ('encrypts and decrypts data', () => {
        const data = '{"data":"Super secret information"}'
        const key = 'Super secure password!!!1111'
        const cypertext = encrypt ({ data, key })

        expect (cypertext).to.not.equal (data)
        expect (decrypt ({ data: cypertext, key })).to.equal (data)
    })
})
