declare module 'serial-number' {
    const serialNumer: {
        (fn: (err: Error, value: string) => void): void,
        preferUUID: boolean,
    }

    export default serialNumer
}
