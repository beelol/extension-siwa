#if defined(DM_PLATFORM_IOS) || defined(DM_PLATFORM_OSX)

#include "siwa.h"

#include <AuthenticationServices/AuthenticationServices.h>

#if defined(DM_PLATFORM_IOS)
#include <UIKit/UIKit.h>
#else
#include <AppKit/AppKit.h>
#endif

#include <dmsdk/sdk.h>

#include <stdlib.h>
#include <string.h>


// The sign in with Apple flow expects us to have a delegate to which it can both pass data from the sign in flow
// but also how to figure out in which UI context it should display the native login UI.
// This class is that delegate.
// It also owns the provider that is both used for the sign in flow, as well as for credential state checking.
API_AVAILABLE(ios(13.0), macos(10.15))
@interface SiwaManager : NSObject <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>
@property (nonatomic, strong) ASAuthorizationAppleIDProvider *m_idProvider;
@property (nonatomic, strong) ASAuthorizationController *m_authController;
@end

@implementation SiwaManager

- (instancetype) init
{
    self = [super init];
    if (self)
    {
        self.m_idProvider = [[ASAuthorizationAppleIDProvider alloc] init];
    }
    return self;
}

// Check if the user id provided to use from lua still grants our app permission
// to use it for sign in. User's can revoke app's permissions to use the id for sign in
// at any time, so we need to be able to monitor this.
// The possible results are revoked(0), authorized(1), and unknown(2).
// In practice, we have recieved unknown when revoking permission to this test app
// so we should treat both revoked and unknown as unauthorized.
- (void) getCredentialState
{
    NSString* userID = [NSString stringWithUTF8String:Siwa_GetUserId() ?: ""];

    [self.m_idProvider getCredentialStateForUserID:userID
            completion: ^(ASAuthorizationAppleIDProviderCredentialState credentialState, NSError* error) {

        // TODO: docs provide no information about what type of errors we can expect:
        // https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidprovider/3175423-getcredentialstateforuserid?language=objc
        if (error) {
            NSString *errorMessage = [NSString stringWithFormat: @"getCredentialStateForUserID completed with error: %@", [error localizedDescription]];
            dmLogError("%s", [errorMessage UTF8String]);
        }

        SiwaCredentialState state = STATE_UNKNOWN;
        switch(credentialState) {
        case ASAuthorizationAppleIDProviderCredentialAuthorized:
            dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialAuthorized");
            state = STATE_AUTHORIZED;
            break;
        case ASAuthorizationAppleIDProviderCredentialRevoked:
            dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialRevoked");
            state = STATE_REVOKED;
            break;
        case ASAuthorizationAppleIDProviderCredentialNotFound:
            dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialNotFound");
            state = STATE_NOT_FOUND;
            break;
        default:
            dmLogInfo("credential state: unknown!!!");
            break;
        }

        Siwa_QueueCredentialCallback([userID UTF8String], state);
    }];
}

// triggers the sign in with Apple native ui flow to begin.
- (void) loginWithUI:(const char*)nonce
{
    ASAuthorizationAppleIDRequest* request = [self.m_idProvider createRequest];
    request.requestedScopes = @[ASAuthorizationScopeFullName, ASAuthorizationScopeEmail];
    if (nonce != 0) {
        request.nonce = [NSString stringWithUTF8String:nonce];
    }

    self.m_authController = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
    self.m_authController.presentationContextProvider = self;
    self.m_authController.delegate = self;

    [self.m_authController performRequests];
}

// the Auth controller needs to specify where to display the native login.
// this is the function our SiwaManager delegate has to implement to provide that information.
- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller {
#if defined(DM_PLATFORM_IOS)
    for (UIScene* scene in [UIApplication sharedApplication].connectedScenes) {
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        for (UIWindow* window in ((UIWindowScene*)scene).windows) {
            if (window.isKeyWindow) {
                return window;
            }
        }
    }
    id<UIApplicationDelegate> delegate = [UIApplication sharedApplication].delegate;
    if ([delegate respondsToSelector:@selector(window)]) {
        UIWindow* window = [(NSObject*)delegate valueForKey:@"window"];
        if (window != nil) {
            return window;
        }
    }
    return nil;
#else
    NSWindow *window = [NSApplication sharedApplication].keyWindow;
    if (window == nil) {
        window = [NSApplication sharedApplication].mainWindow;
    }
    return window;
#endif
}

// the Auth controller callback for getting a response back from apple for a sign in
- (void)authorizationController:(ASAuthorizationController *)controller
didCompleteWithAuthorization:(ASAuthorization *)authorization {
    if ([authorization.credential class] == [ASAuthorizationAppleIDCredential class]) {
        ASAuthorizationAppleIDCredential* appleIdCredential = ((ASAuthorizationAppleIDCredential*) authorization.credential);

        const char* appleUserId = [appleIdCredential.user UTF8String];
        const char* email = [appleIdCredential.email UTF8String];
        const char* givenName = [appleIdCredential.fullName.givenName UTF8String];
        const char* familyName = [appleIdCredential.fullName.familyName UTF8String];
        SiwaUserDetectionStatus userDetectionStatus = STATUS_UNSUPPORTED;
        if (appleIdCredential.realUserStatus == ASUserDetectionStatusLikelyReal)
        {
            userDetectionStatus = STATUS_LIKELY_REAL;
        }
        else if (appleIdCredential.realUserStatus == ASUserDetectionStatusUnknown)
        {
            userDetectionStatus = STATUS_UNKNOWN;
        }

        NSString* tokenString = [[NSString alloc] initWithData:appleIdCredential.identityToken encoding:NSUTF8StringEncoding];
        const char* identityToken = [tokenString UTF8String];

        if (identityToken == 0 || appleUserId == 0) {
            Siwa_QueueAuthFailureCallback("Apple authorization returned incomplete credentials");
            self.m_authController = nil;
            return;
        }

        Siwa_QueueAuthSuccessCallback(identityToken, appleUserId, email, givenName, familyName, userDetectionStatus);
    }
    else
    {
        Siwa_QueueAuthFailureCallback("authorization failed!");
    }
    self.m_authController = nil;
}

// The Auth controller callback for getting an error during authorization
- (void)authorizationController:(ASAuthorizationController *)controller
didCompleteWithError:(NSError *)error {
    NSString *errorMessage = [NSString stringWithFormat: @"Authorization error: %@", [error localizedDescription]];
    Siwa_QueueAuthFailureCallback([errorMessage UTF8String]);
    self.m_authController = nil;
}

@end


API_AVAILABLE(ios(13.0), macos(10.15))
static SiwaManager* g_SiwaManager = nil;

API_AVAILABLE(ios(13.0), macos(10.15))
SiwaManager* GetSiwaManager()
{
    if(g_SiwaManager == nil)
    {
        g_SiwaManager = [[SiwaManager alloc] init];
    }

    return g_SiwaManager;
}

API_AVAILABLE(ios(13.0), macos(10.15))
// Kicks off the request to get the credential state of a provided user id.
void Siwa_PlatformDoGetCredentialState() {
    SiwaManager *siwaMan = GetSiwaManager();
    [siwaMan getCredentialState];
    return;
}

API_AVAILABLE(ios(13.0), macos(10.15))
// Kicks off the sign in with apple flow.
void Siwa_PlatformDoAuthenticateWithApple(const char* nonce) {
    SiwaManager *siwaMan = GetSiwaManager();
    [siwaMan loginWithUI:nonce];
}

// Checks if Siwa is supported on this device by seeing if the main
// class involved in all the siwa requests we use exists.
bool Siwa_PlatformIsSupported()
{
    return ([ASAuthorizationAppleIDProvider class] != nil);
}

void Siwa_PlatformGetCredentialState() {
    Siwa_PlatformDoGetCredentialState();
}

void Siwa_PlatformAuthenticateWithApple(const char* nonce) {
    Siwa_PlatformDoAuthenticateWithApple(nonce);
}

#endif
