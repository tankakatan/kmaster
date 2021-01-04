import { createKeys } from '../src/scrambler'

describe ('scrambler', function () {

    this.timeout(5000)

    it ('generates a new keypair', async () => {
        const key = await createKeys ({
            name: 'Test',
            email: 'test@test.com',
            passphrase: 'Test test test test test test'
        })

        await key.revoke ()
    })
})
