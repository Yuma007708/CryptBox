import { Capacitor } from '@capacitor/core';

/** Capacitor で包まれたネイティブアプリ内で動いているか */
export const isNative: boolean = Capacitor.isNativePlatform();

/** 'ios' | 'android' | 'web' */
export const platform: string = Capacitor.getPlatform();

export const isIOS = platform === 'ios';
export const isAndroid = platform === 'android';
