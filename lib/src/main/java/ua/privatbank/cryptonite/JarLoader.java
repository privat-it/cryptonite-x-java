/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

package ua.privatbank.cryptonite;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;

final class JarLoader {

    public static String LIB_PATH = "";

    static {
        try {
            File temp = File.createTempFile("cryptonite_", "");
            temp.delete();
            temp.mkdir();
            LIB_PATH = temp.getAbsolutePath();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String loadJarLib(final String libName) {
        final String libFile = getLibFile(libName);
        final String loadPath = "libs/" + getLibDir() + "/" + libFile;
        final String savePath = Paths.get(LIB_PATH, libFile).toString();

        if (!new File(savePath).exists()) {
            try {
                final InputStream is = getResourceAsStream(loadPath);
                final OutputStream os = new FileOutputStream(savePath);
                byte[] buffer = new byte[1024];
                while (is.available() > 0) {
                    int len = is.read(buffer, 0, buffer.length);
                    os.write(buffer, 0, len);
                }

                os.flush();
                os.close();
                is.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return libFile;
    }

    private static InputStream getResourceAsStream(String resourceName) {
        ClassLoader[] cls = new ClassLoader[] { ClassLoader.getSystemClassLoader(), JarLoader.class.getClassLoader(),
                Thread.currentThread().getContextClassLoader() };

        for (ClassLoader cl : cls) {
            if (cl == null) {
                continue;
            }

            InputStream is;
            if ((is = cl.getResourceAsStream(resourceName)) != null) {
                return is;
            }
        }

        return null;
    }

    private static String getLibDir() {
        final String name = System.getProperty("os.name").toLowerCase();
        final String arch = System.getProperty("os.arch").endsWith("64") ? "x86-64" : "x86";
        final String os;

        if (name.startsWith("win")) {
            os = "windows";
        } else if (name.startsWith("linux")) {
            os = "linux";
        } else {
            os = "unix";
        }

        return os + "_" + arch;
    }

    private static String getLibFile(final String libName) {
        final String osName = System.getProperty("os.name").toLowerCase();
        final String libFile;

        if (osName.startsWith("win")) {
            libFile = libName + ".dll";
        } else if (osName.startsWith("linux")) {
            libFile = "lib" + libName + ".so";
        } else {
            libFile = "lib" + libName + ".so";
        }

        return libFile;
    }
}
