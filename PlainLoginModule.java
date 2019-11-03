import java.io.IOException;
import java.util.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Hex;
import java.io.FileNotFoundException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

 
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
 
/**
 * Login module that simply matches name and password to perform authentication.
 * If successful, set principal to name and credential to "admin".
 *
 * @author Nicolas Fränkel
 * @since 2 avr. 2009
 */
public class PlainLoginModule implements LoginModule {
 
    /** Callback handler to store between initialization and authentication. */
    private CallbackHandler handler;
 
    /** Subject to store. */
    private Subject subject;
 
    /** Login name. */
    private String login;

    private PlainUserPrincipal userPrincipal;
	private PlainRolePrincipal rolePrincipal;
    private List<String> userGroups;
    private List<String> rolesFromFile;
 
    /**
     * This implementation always return false.
     *
     * @see javax.security.auth.spi.LoginModule#abort()
     */
    @Override
    public boolean abort() throws LoginException {
 
        return false;
    }
 
    /**
     * This is where, should the entire authentication process succeeds,
     * principal would be set.
     *
     * @see javax.security.auth.spi.LoginModule#commit()
     */
    @Override
    public boolean commit() throws LoginException {
 
 
        userPrincipal = new PlainUserPrincipal(login);
        subject.getPrincipals().add(userPrincipal);
        
		if (userGroups != null && userGroups.size() > 0) {
			for (String groupName : userGroups) {
				rolePrincipal = new PlainRolePrincipal(groupName);
				subject.getPrincipals().add(rolePrincipal);
			}
		}

		return true;
    }
 
    /**
     * This implementation ignores both state and options.
     *
     * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject,
     *      javax.security.auth.callback.CallbackHandler, java.util.Map,
     *      java.util.Map)
     */
    @Override
    public void initialize(Subject aSubject, CallbackHandler aCallbackHandler, Map aSharedState, Map aOptions) {
 
        handler = aCallbackHandler;
        subject = aSubject;
    }
 
    /**
     * This method checks whether the name and the password are the same.
     *
     * @see javax.security.auth.spi.LoginModule#login()
     */
    @Override
    public boolean login() throws LoginException, FailedLoginException {
 
          Callback[] callbacks = new Callback[2];
	 callbacks[0] = new NameCallback("login");
	 callbacks[1] = new PasswordCallback("password", true);

	try {
            handler.handle(callbacks);
	        String name = ((NameCallback) callbacks[0]).getName();
            String password = String.valueOf(((PasswordCallback) callbacks[1]).getPassword());
            boolean verifyCredentials = verifyCredentials(name , password);
            subject.getPrincipals().add(new PlainUserPrincipal(name));
            login=name;
            rolesFromFile = loadRoles(name);
            userGroups = new ArrayList<String>();
            Collections.copy(userGroups, rolesFromFile);
            System.out.println("Roles a asociar " + userGroups);
//            userGroups.add("AC");     
            return true;
	

		} catch (IOException e) {
			throw new LoginException(e.getMessage());
		} catch (UnsupportedCallbackException e) {
			throw new LoginException(e.getMessage());
        }   catch (InvalidKeySpecException ex) {
                Logger.getLogger(PlainLoginModule.class.getName()).log(Level.SEVERE, null, ex);
            }
        
        throw new FailedLoginException();
    }

    public boolean verifyCredentials (String name, String password) throws FailedLoginException, LoginException, InvalidKeySpecException {
        try {
            String catalina = System.getProperty("catalina.home");
            catalina+="/lib/users.txt";
            Scanner fileScan = new Scanner (new File(catalina));
            while (fileScan.hasNextLine() ) {
            String input = fileScan.nextLine();
            boolean respuesta = parseLine(input, name, password); 
            if (respuesta) {
                return true;
            }
        }

        // If credentials are NOT OK we throw a LoginException
        throw new LoginException("Authentication failed");
          
        } catch (IOException e) {
            System.out.println("File Read Error");
        }
        return true;
    }
    
    private static boolean parseLine(String str, String name, String password) throws  InvalidKeySpecException{
        String username, hash, salt, pepper;
        Scanner sc = new Scanner(str);
        sc.useDelimiter(",");

        while(sc.hasNext()){
         username = sc.next();
         hash = sc.next();
         salt = sc.next();
         pepper = sc.next();
         password+=pepper;
		 int iterations = 10;
         int keyLength = 512;
		 char[] passwordChars = password.toCharArray();
		 byte[] saltBytes = salt.getBytes();
		 byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
         String hashedString = Hex.encodeHexString(hashedBytes);
        if (name != null && name.equals(username) && password != null && hashedString.equals(hash)) {
            return true;
        } 
        }
        sc.close();
        return false;
       } 
	
	public static byte[] hashPassword( final char[] password, final byte[] salt, final int iterations, final int keyLength ) throws InvalidKeySpecException {

		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
			PBEKeySpec spec = new PBEKeySpec( password, salt, iterations, keyLength );
			SecretKey key = skf.generateSecret( spec );
			byte[] res = key.getEncoded( );
			return res;
		} catch ( NoSuchAlgorithmException e ) {
			throw new RuntimeException( e );
		}
    }
    
    private List<String> loadRoles (String name) throws FileNotFoundException {
        List<String> roles; 
        String cata = System.getProperty("catalina.home");
        cata+="/lib/roles.txt";
        Scanner fileScan = new Scanner (new File(cata));
        while (fileScan.hasNextLine() ) {
            String input = fileScan.nextLine();
            roles = parseLine2(input, name);
            System.out.println("Roles en la lista" + roles);
            return roles;
        }
        return Collections.emptyList();
   }

   private static List<String> parseLine2(String str, String name) {
    String username, rol ;
    Scanner sc = new Scanner(str);
    sc.useDelimiter(":");

    while(sc.hasNext()){
        username = sc.next();
        rol = sc.next();
        if (name != null && name.equals(username)) {
            System.out.println("Roles en el archivo" + rol + "usuario" + username);
            List<String> items = Arrays.asList(rol.split("\\s*,\\s*"));
            return items;
        } 
    }
    sc.close();
    return Collections.emptyList();
   }

 
    /**
     * Clears subject from principal and credentials.
     *
     * @see javax.security.auth.spi.LoginModule#logout()
     */
    @Override
    public boolean logout() throws LoginException {
 
        try {
 
            subject.getPrincipals().remove(userPrincipal);
            subject.getPrincipals().remove(rolePrincipal);
 
            return true;
 
        } catch (Exception e) {
 
            throw new LoginException(e.getMessage());
        }
    }
}
