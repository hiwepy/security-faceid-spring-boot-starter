package org.springframework.security.boot.faceid.authentication;

import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.faceid.exception.AuthenticationFaceIDNotFoundException;
import org.springframework.security.boot.faceid.userdetails.FaceInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

/**
 * Authenticates a face-ID authentication request. <p>Delegates face matching to a
 * {@link FaceRecognitionProvider}, loads the corresponding user details via a
 * {@link UserDetailsServiceAdapter} and validates the account status before returning a
 * fully authenticated {@link FaceIDAuthenticationToken}.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class FaceIDAuthenticationProvider implements AuthenticationProvider {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final FaceRecognitionProvider faceRecognitionProvider;
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    /**
     * Constructs a provider with the given face-recognition strategy and user-details service.
     * @param faceRecognitionProvider the strategy used to resolve face information
     * @param userDetailsService the adapter used to load user details
     */
    public FaceIDAuthenticationProvider(final FaceRecognitionProvider faceRecognitionProvider,
    		final UserDetailsServiceAdapter userDetailsService) {
    	this.faceRecognitionProvider = faceRecognitionProvider;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Authenticates the given token.
     * <p>The returned object is ultimately stored in the security context via
     * {@code SecurityContextHolder.getContext().setAuthentication(authResult)}.</p>
     * @author [@Loong Wan](https://github.com/loong10k)
     * @param authentication the {@link FaceIDAuthenticationToken} to authenticate
     * @return the fully authenticated {@link Authentication} object
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
    	InputStream faceStream = (InputStream) authentication.getPrincipal();
        if (faceStream == null) {
			logger.debug("No principal found in request.");
			throw new BadCredentialsException("No principal found in request.");
		}
        
        // load face info by face image
        FaceInfo faceInfo = getFaceRecognitionProvider().loadFaceInfo(authentication);
        if (faceInfo == null) {
			logger.debug("No face info found by face image.");
			throw new AuthenticationFaceIDNotFoundException("No face info found by face image.");
		}
        
        // load user details by face info
		UserDetails ud = getUserDetailsService().loadUserDetails(new FaceIDAuthenticationToken(faceInfo));
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        FaceIDAuthenticationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	authenticationToken = new FaceIDAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new FaceIDAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    /**
     * Returns whether this provider supports the given authentication token type.
     * @param authentication the token type to check
     * @return {@code true} if the token is assignable to {@link FaceIDAuthenticationToken}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (FaceIDAuthenticationToken.class.isAssignableFrom(authentication));
    }

	/**
	 * Sets the checker used to validate the account status of loaded users.
	 * @param userDetailsChecker the user-details checker
	 */
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	/**
	 * Returns the checker used to validate the account status of loaded users.
	 * @return the user-details checker
	 */
	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	/**
	 * Returns the face-recognition strategy used by this provider.
	 * @return the face-recognition provider
	 */
	public FaceRecognitionProvider getFaceRecognitionProvider() {
		return faceRecognitionProvider;
	}

	/**
	 * Returns the user-details adapter used by this provider.
	 * @return the user-details service
	 */
	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}

}
