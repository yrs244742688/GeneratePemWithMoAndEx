//
//  DetailViewController.h
//  TestRSA
//
//  Created by YangXu on 15/4/27.
//  Copyright (c) 2015年 365sji. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface DetailViewController : UIViewController

@property (strong, nonatomic) id detailItem;
@property (weak, nonatomic) IBOutlet UILabel *detailDescriptionLabel;

@end

