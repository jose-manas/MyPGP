package gui;

import keys.Key;

import java.io.File;

public class SignedItem {
    public final File file;
    public final Key signer;
    public final boolean verify;

    public SignedItem(File file, Key signer, boolean verify) {
        this.file = file;
        this.signer = signer;
        this.verify = verify;
    }
}
