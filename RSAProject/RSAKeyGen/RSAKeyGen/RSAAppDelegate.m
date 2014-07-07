//
//  RSAAppDelegate.m
//  RSAKeyGen
//
//  Created by Dmitry Starkoff on 6/26/12.
//  Copyright (c) 2012 SoftTeco. All rights reserved.
//

#import "RSAAppDelegate.h"
#import "SecKeyWrapper.h"
#import "NSData+Base64.h"
@interface RSAAppDelegate ()
- (void)generateRSAKeys:(unsigned)length;
@end

@implementation RSAAppDelegate

@synthesize window = _window;

- (void)dealloc
{
    [_window release];
    [super dealloc];
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    self.window = [[[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]] autorelease];
    // Override point for customization after application launch.
    self.window.backgroundColor = [UIColor whiteColor];
    [self.window makeKeyAndVisible];
    [self generateRSAKeys:1024];
    return YES;
}

- (void)generateRSAKeys:(unsigned)length {
    //================================================>>>>>>>>>>>>
    SecKeyWrapper * keyWrapper = [SecKeyWrapper sharedWrapper];
    [keyWrapper generateKeyPair:length];
    NSArray * paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString * pathForPublicKey = [paths objectAtIndex:0];
    NSString * pathForPrivateKey = [paths objectAtIndex:0];
    [[NSFileManager defaultManager] createDirectoryAtPath:[pathForPrivateKey stringByAppendingPathComponent:@".ssh"]
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    //====================<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    pathForPublicKey = [pathForPublicKey stringByAppendingPathComponent:@".ssh/id_rsa.pub"];

    pathForPrivateKey = [pathForPrivateKey stringByAppendingPathComponent:@".ssh/id_rsa"];

    char lenth[4] = {0,0,0,7};
    NSMutableData * data = [NSMutableData dataWithBytes:lenth length:4];
    NSString * strPK = @"ssh-rsa"; //Here is at first public key
    [data appendData:[strPK dataUsingEncoding:NSUTF8StringEncoding]];
    lenth[3] = 3;
    [data appendBytes:lenth length:4];
    char v[3] = {1,0,1};
    [data appendBytes:v length:3];
    lenth[3] = [[keyWrapper getPublicKeyMod] length];
    [data appendBytes:lenth length:4];
    [data appendData:[keyWrapper getPublicKeyMod]];
    NSLog(@"ssh-rsa %@\n",[data base64EncodingWithLineLength:0]);
    NSLog(@"Exponent: length:%d %@\n",[[keyWrapper getPublicKeyExp] length],[[keyWrapper getPublicKeyExp] base64EncodingWithLineLength:0]);
    NSLog(@"Modulus: length:%d %@\n",[[keyWrapper getPublicKeyMod] length],[[keyWrapper getPublicKeyMod] base64EncodingWithLineLength:0]);

    strPK = @"ssh-rsa ";
    strPK = [strPK stringByAppendingString:[data base64EncodingWithLineLength:0]];
    strPK = [strPK stringByAppendingString:@" www.address.com\n"];
    //Saving public key
    BOOL b = [strPK writeToFile:pathForPublicKey atomically:YES encoding:NSUTF8StringEncoding error:nil];
    printf("public: %s save successful: %s\n",[pathForPublicKey cStringUsingEncoding:NSASCIIStringEncoding],b?"true":"false");
    NSLog(@"public key: length:%d %@\n",[[keyWrapper getPublicKeyBits] length],[[keyWrapper getPublicKeyBits] description]);
    //================================================>>>>>>>>>>>>
    strPK = @"-----BEGIN RSA PRIVATE KEY-----\n"; //Now here is private key
    NSLog(@"private key size - %d\n",[[keyWrapper getPrivateKeyBits] length]);
    strPK = [strPK stringByAppendingString:[[keyWrapper getPrivateKeyBits] base64EncodingWithLineLength:64]];
    strPK = [strPK stringByAppendingString:@"\n-----END RSA PRIVATE KEY-----\n"];
    //Saving private key
    b = [strPK writeToFile:pathForPrivateKey atomically:YES encoding:NSUTF8StringEncoding error:nil];
    printf("private: %s save successful: %s\n",[pathForPrivateKey cStringUsingEncoding:NSASCIIStringEncoding],b?"true":"false");
    NSNumber * permisstion = [NSNumber numberWithLong:0x0700];
    NSDictionary * dict = [NSDictionary dictionaryWithObject:permisstion forKey:NSFilePosixPermissions];
    b = [[NSFileManager defaultManager] setAttributes:dict ofItemAtPath:pathForPrivateKey error:nil];
    printf("attribs bool: %s\n",b?"true":"false");
    NSLog(@"private key: length:%d %@\n",[[keyWrapper getPrivateKeyBits] length],[[keyWrapper getPrivateKeyBits] description]);
    //====================<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    NSLog(@"ssh-rsa key block size: %zu",SecKeyGetBlockSize([keyWrapper getPublicKeyRef]));
}

- (void)applicationWillResignActive:(UIApplication *)application
{
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later. 
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application
{
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
