package com.contrastsecurity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Optional;

import org.apache.commons.codec.digest.DigestUtils;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Hash;
import org.junit.Test;


public class LibrariesTest {

    @Test
    public void testFile() throws Exception {
        File jar = getPathToResource("/spring-petclinic-1.5.1.jar");
        Jbom jbom = new Jbom();
        Libraries libs = jbom.doLocalFile( jar, "target/test" );
        assertTrue( "Incorrect number of libraries found. " + libs.getLibraries().size() + " instead of 135", libs.getLibraries().size() == 135 );
        compareHashToFile(jar,libs,"petclinic");
        assertEquals("8ef0a3efc567782abda2feac290ce1ffad85f045", hashFileSHA1(jar));

        String sha1 = Libraries.hash(Files.newInputStream(jar.toPath()), MessageDigest.getInstance("SHA1") );
        assertEquals("8ef0a3efc567782abda2feac290ce1ffad85f045", sha1);
    }

    @Test
    public void testFileCallBack() throws Exception {
        File jar = getPathToResource("/callback-2.18.0-SNAPSHOT.jar");
        Jbom jbom = new Jbom();
        Libraries libs = jbom.doLocalFile( jar, "target/test" );
        assertTrue( "Incorrect number of libraries found. " + libs.getLibraries().size() + " instead of 102", libs.getLibraries().size() == 102 );
        compareHashToFile(jar,libs,"callback");
    }

    @Test
    public void testNoComponents() throws Exception {
        File jar = getPathToResource("/nocomponents.jar");
        Jbom jbom = new Jbom();
        Libraries libs = jbom.doLocalFile( jar, "target/test" );
        assertTrue( "Incorrect number of libraries found. " + libs.getLibraries().size() + " instead of 0", libs.getLibraries().size() == 0 );
    }

    @Test
    public void testFileWithShading() throws Exception {
        File jar = getPathToResource("/provider-search-0.0.1-SNAPSHOT.jar");
        Jbom jbom = new Jbom();
        Libraries libs = jbom.doLocalFile( jar, "target/test" );
        assertTrue( "Incorrect number of libraries found. " + libs.getLibraries().size() + " instead of 26", libs.getLibraries().size() == 26 );
        compareHashToFile(jar,libs,"provider-search");
    }

    @Test
    public void testDir() throws Exception {
        File jar = getPathToResource("/");
        Jbom jbom = new Jbom();
        Libraries libs = jbom.doLocalDirectory( jar.getAbsolutePath(), "target/test" );
        assertTrue( "Incorrect number of libraries found. " + libs.getLibraries().size() + " instead of 266", libs.getLibraries().size() == 266 );
    }

    private File getPathToResource(String path) throws URISyntaxException {
        return new File(LibrariesTest.class.getResource(path).toURI());
    }

    private void compareHashToFile(File file, Libraries libs, String libName) throws IOException {
        Optional<Component> component = libs.getLibraries().stream().filter(lib->lib.getName().contains(libName)).findFirst();
        if(!component.isPresent()) {
            fail("Library : " + libName + " cannot be found");
        } else {
            String sha1FromLib = component.get().getHashes().stream().filter(h->h.getAlgorithm().equals("SHA-1")).map(Hash::getValue).findFirst().orElse("SHA1 Hash Not Found");
            String md5FromLib = component.get().getHashes().stream().filter(h->h.getAlgorithm().equals("MD5")).map(Hash::getValue).findFirst().orElse("MD5 Hash Not Found");

            assertEquals(hashFileSHA1(file),sha1FromLib);
            assertEquals(hashFileMD5(file),md5FromLib);
        }

    }

    private String hashFileSHA1(File path) throws IOException {
        return DigestUtils.sha1Hex(new FileInputStream(path));
    }

    private String hashFileMD5(File path) throws IOException {
        return DigestUtils.md5Hex(new FileInputStream(path));
    }

}