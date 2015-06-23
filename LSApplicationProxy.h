@interface LSApplicationProxy

@property(readonly) NSString * applicationIdentifier;
@property(readonly) NSString * applicationType;
@property(readonly) BOOL fileSharingEnabled;
@property(readonly) BOOL profileValidated;

+ (id)applicationProxyForIdentifier:(NSString *)identifier placeholder:(BOOL)placeholder;
- (NSURL *)dataContainerURL;

@end
