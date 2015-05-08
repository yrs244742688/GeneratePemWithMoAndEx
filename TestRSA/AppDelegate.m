//
//  AppDelegate.m
//  TestRSA
//
//  Created by YangXu on 15/4/27.
//  Copyright (c) 2015年 365sji. All rights reserved.
//

#import "AppDelegate.h"
#import "DetailViewController.h"
#import "RSAHelper.h"

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Override point for customization after application launch.
    
    RSAHelper *helper = [RSAHelper sharedInstance];
#if 1 // J's data
    BOOL isOk = [helper generatePemWithMo:@"MTQ5NzEwNDQ0MDU5NzQyNTc5NDE4MDAzMTM2MzA3NTA2Njg3OTE4NjcwMzgwNDczMjI4NjE5OTc0NzE4NTQyNTgxMTkxNjgzNzgzNzg0MDEzODUxNzY0NzU3NjUxMzYzMjIyMDY2OTE5Mzc1MTM3MjA2ODcyODI4NjM5OTUwNTE1MzI2NzM0NzAxMTE5Nzk1MzAxMjA2NzQ4MTM5OTkxNjUxMjExNzI1NjQ0MjA3MjkyODIyNzI4Njg3NjU3NTIyMzMzMzMzMDgyMDI2MDU1MzY3OTg5MzYwODE1ODE5NjQwNDM4NTExODQyNzcwOTgxMDkyMjQ5MjM1MDg1MjQ5Mjc1NDc0NjIxMjM0MjkyMTUwNDQ5OTUwNTQ2NDAyNzY5MjM4NTQyOTA5MTgyNTA5ODI2MTAx" ex:@"NjU1Mzc="];
#else  // My data
    BOOL isOk = [helper generatePemWithMo:@"wVwBKuePO3ZZbZ//gqaNuUNyaPHbS3e2v5iDHMFRfYHS/bFw+79GwNUiJ+wXgpA7SSBRhKdLhTuxMvCn1aZNlXaMXIOPG1AouUMMfr6kEpFf/V0wLv6NCHGvBUK0l7O+2fxn3bR1SkHM1jWvLPMzSMBZLCOBPRRZ5FjHAy8d378=" ex:@"AQAB"];

#endif
    
    if (isOk) {
        NSLog(@"111");
    } else {
        NSLog(@"000");
    }
    
    NSLog(@"%@", [helper encryString:@"12312321"]);
    
    return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
