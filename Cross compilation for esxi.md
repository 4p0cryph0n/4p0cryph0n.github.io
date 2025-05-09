Yes, it is possible to download older versions of `libssl` and `libcrypto` shared libraries and use them for compilation. Here’s how you can do it:

### Steps to Download and Use Older Versions of `libssl` and `libcrypto`

#### 1. **Download Older Versions**

You can download older versions of OpenSSL (which include `libssl` and `libcrypto` shared libraries) from the OpenSSL archive or other trusted repositories. For example, OpenSSL 1.0.2 can be downloaded from the OpenSSL [archives](https://www.openssl.org/source/).

Here’s a direct link for OpenSSL 1.0.2u:

```sh
wget https://www.openssl.org/source/openssl-1.0.2u.tar.gz
```

#### 2. **Extract the Tarball**

Extract the tarball:

```sh
tar -xzf openssl-1.0.2u.tar.gz
```

#### 3. **Build and Install OpenSSL**

Change to the directory containing the extracted files:

```sh
cd openssl-1.0.2u
```

Configure, build, and install OpenSSL:

```sh
./config
make
sudo make install
```

By default, this installs OpenSSL in `/usr/local/ssl`.

#### 4. **Set Library Path (if needed)**

If you installed OpenSSL in a non-standard location, you need to set the library path. You can do this by updating the `LD_LIBRARY_PATH` environment variable:

```sh
export LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH
```

Add the path to the system’s library path configuration:

```sh
echo "/usr/local/ssl/lib" | sudo tee -a /etc/ld.so.conf.d/openssl.conf
sudo ldconfig
```

#### 5. **Compile Your Code with Specific Library Paths**

When compiling your code, you may need to specify the include and library paths to point to the older OpenSSL version:

```sh
gcc -o your_program your_program.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto
```

### Summary

1. **Download the old OpenSSL version tarball.**
2. **Extract the tarball.**
3. **Build and install OpenSSL.**
4. **Update library paths if necessary.**
5. **Compile your code with the specific paths to the old OpenSSL libraries.**

This process ensures that you are using the specific versions of `libssl` and `libcrypto` that match the OpenSSL version you need for your project.




To ensure that you are using the version of `libssl` and `libcrypto` provided by OpenSSL 1.0.2 and not the system's default version, you need to properly configure and set up your environment to prioritize the libraries you installed. Here are the steps you should follow:

### 1. **Set Up Library Paths**

When you install OpenSSL from source, it typically installs libraries to `/usr/local/ssl` by default. You need to set your system's library path to use these libraries instead of the system's default ones.

#### Update `LD_LIBRARY_PATH`

Add the directory where OpenSSL libraries are installed to the `LD_LIBRARY_PATH` environment variable:

```sh
export LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH
```

You can add this line to your shell’s configuration file (`~/.bashrc`, `~/.bash_profile`, or `~/.profile`) to make it persistent:

```sh
echo 'export LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

#### Update the Library Cache

You should also update the system’s library cache so that it recognizes the new libraries:

1. Create a configuration file for the new library path:

   ```sh
   echo "/usr/local/ssl/lib" | sudo tee /etc/ld.so.conf.d/openssl.conf
   ```

2. Update the library cache:

   ```sh
   sudo ldconfig
   ```

### 2. **Verify the OpenSSL Version**

After setting up the environment, verify that the OpenSSL version is 1.0.2. You can use the OpenSSL command-line tool that comes with the installed OpenSSL 1.0.2:

```sh
/usr/local/ssl/bin/openssl version
```

This should return:

```
OpenSSL 1.0.2u  20 Dec 2019
```

### 3. **Compile with the Specific OpenSSL Version**

When compiling programs that use OpenSSL, make sure to specify the include and library paths of your OpenSSL 1.0.2 installation:

```sh
gcc -o your_program your_program.c -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto
```

### 4. **Check Runtime Library Usage**

To confirm that your application uses the OpenSSL 1.0.2 libraries at runtime, you can use `ldd` on your compiled binary to check which libraries it is linked against:

```sh
ldd your_program
```

Look for `libssl.so.1.0.2` and `libcrypto.so.1.0.2` in the output. They should point to `/usr/local/ssl/lib`.

### Summary

1. **Set `LD_LIBRARY_PATH`** to include `/usr/local/ssl/lib`.
2. **Update library cache** using `ldconfig`.
3. **Verify OpenSSL version** using the OpenSSL binary from `/usr/local/ssl/bin`.
4. **Compile with the correct paths** to OpenSSL 1.0.2.
5. **Check runtime library usage** with `ldd`.

Following these steps will ensure that your system and applications use the OpenSSL 1.0.2 libraries you installed instead of the system’s default version.


The error message `/lib64/libc.so.6: version 'GLIBC_2.33' not found` indicates that your binary is linked against a version of `glibc` that is not available on your system. To resolve this, you have a few options:

### 1. **Static Linking (Preferred if Feasible)**

Link your binary statically with `glibc` to avoid dependency on the system's `glibc` version. This includes all required libraries in the binary itself.

#### Steps to Static Linking:

1. **Ensure Static Libraries Are Available:**
   Install the static versions of the libraries you need. For `glibc`, this is usually done through your package manager.

2. **Compile with Static Linking:**
   Add `-static` to your GCC compilation command.

   ```sh
   gcc -static -o encrypt_vm_files encrypt_vm_files.c -lssl -lcrypto
   ```

   Note that static linking may not always be feasible, especially with libraries like `glibc` due to size constraints and compatibility issues.

### 2. **Compile Against an Older Version of `glibc`**

Recompile your binary using a version of `glibc` that is compatible with your target environment. You would need to:

1. **Download and Extract the Older `glibc` Version:**

   ```sh
   wget http://ftp.gnu.org/gnu/libc/glibc-2.30.tar.gz
   tar -xzf glibc-2.30.tar.gz
   ```

2. **Compile and Install Locally:**

   ```sh
   cd glibc-2.30
   mkdir build
   cd build
   ../configure --prefix=/path/to/local/glibc
   make
   make install
   ```

3. **Compile Your Binary Using the Older `glibc`:**

   Use the `LD_LIBRARY_PATH` to point to the directory where the older `glibc` is installed:

   ```sh
   gcc -o encrypt_vm_files encrypt_vm_files.c -L/path/to/local/glibc/lib -Wl,--rpath=/path/to/local/glibc/lib -lssl -lcrypto
   ```

   Ensure that you use the correct version of `libssl` and `libcrypto` as well.

### 3. **Cross-compile for Compatibility**

If you are developing for a different environment, consider using cross-compilation to build your binary in a compatible environment:

1. **Set Up a Cross-compilation Toolchain:**
   Create or obtain a cross-compilation toolchain that matches the target system's libraries and headers.

2. **Compile with the Toolchain:**

   ```sh
   export CC=/path/to/cross-compiler-gcc
   export CFLAGS="-I/path/to/cross-compiler/include"
   export LDFLAGS="-L/path/to/cross-compiler/lib"
   $CC -o encrypt_vm_files encrypt_vm_files.c -lssl -lcrypto
   ```

### Summary

To fix the `GLIBC_2.33` error, the recommended approach is to:

1. **Try Static Linking:** This avoids dependency on the system's `glibc`.
2. **Compile Against a Compatible Version of `glibc`:** Ensure you are linking against a version of `glibc` that is available on your system.
3. **Cross-compile:** Use a compatible environment to ensure your binary matches the target system's requirements.

Choose the approach that best fits your constraints and development environment.

Let's replace the placeholders with actual paths based on a typical setup where you've installed OpenSSL and glibc locally on your development machine.

Assuming:
- OpenSSL 1.0.2u is installed at `/usr/local/openssl-1.0.2`
- glibc 2.30 is installed at `/usr/local/glibc-2.30`

### Set Up Environment Variables for Cross-Compilation

Replace `<cross-compiler>` and `<cross-compiler-cxx>` with the appropriate cross-compilation tools for your target architecture, like `x86_64-linux-gnu-gcc` for x86_64 architecture:

```bash
export CC=x86_64-linux-gnu-gcc
export CXX=x86_64-linux-gnu-g++
export CFLAGS="-I/usr/local/openssl-1.0.2/include -I/usr/local/glibc-2.30/include"
export LDFLAGS="-L/usr/local/openssl-1.0.2/lib -L/usr/local/glibc-2.30/lib"
```

### Build Commands for OpenSSL and glibc

Assuming you have downloaded and extracted OpenSSL and glibc:

#### OpenSSL 1.0.2u

```bash
cd openssl-1.0.2u
./Configure no-shared --prefix=/usr/local/openssl-1.0.2
make
make install
```

#### glibc 2.30

```bash
cd glibc-2.30
mkdir build
cd build
../configure --prefix=/usr/local/glibc-2.30
make
make install
```

### Compile Your Binary

With the environment variables set, compile your binary using the cross-compiler:

```bash
x86_64-linux-gnu-gcc -o my_binary my_source.c $CFLAGS $LDFLAGS -lssl -lcrypto -static-libgcc -Wl,-Bstatic,-lc,-lgcc_s,-lgcc,-Bdynamic
```

### Summary

- OpenSSL is located at `/usr/local/openssl-1.0.2`
- glibc is located at `/usr/local/glibc-2.30`
- You’re using `x86_64-linux-gnu-gcc` as your cross-compiler for a 64-bit Linux target.

This setup ensures your binary is compiled against OpenSSL 1.0.2u and glibc 2.30, which you installed locally. The use of static linking helps mitigate compatibility issues with different versions of glibc on the target system.




```sh
x86_64-linux-gnu-gcc -o encrypt_vm_files encrypt_vm_files.c sosemanuk.c $CFLAGS $LDFLAGS -lssl -lcrypto -ldl -static-libgcc
```

