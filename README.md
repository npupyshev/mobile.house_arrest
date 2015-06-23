# mobile.house_arrest
A rewrite of com.apple.mobile.house_arrest service, which is used to access app containers over USB (like iFunbox). The code is a bit dirty.
# build
 xcrun -sdk iphoneos clang house_arrest.m -o mobile_house_arrest -arch armv7 -arch arm64 -llockdown -lafc -lobjc -framework MobileCoreServices -framework CoreFoundation
