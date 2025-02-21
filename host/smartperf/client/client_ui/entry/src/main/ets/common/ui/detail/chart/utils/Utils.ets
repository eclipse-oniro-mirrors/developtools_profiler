/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Paint, {TextPaint, ImagePaint} from '../data/Paint'
import MyRect from '../data/Rect'
import FSize from './FSize'
import MPPointF from './MPPointF'
import IValueFormatter from '../formatter/IValueFormatter';
import DefaultValueFormatter from '../formatter/DefaultValueFormatter';
import deviceInfo from '@ohos.deviceInfo';
/**
 * Utilities class that has some helper methods. Needs to be initialized by
 * calling Utils.init(...) before usage. Inside the Chart.init() method, this is
 * done, if the Utils are used before that, Utils.init(...) needs to be called
 * manually.
 *
 * @author Philipp Jahoda
 */
export default abstract class Utils {
  private static scaledDensity: number = 3.3125;
  private static mMinimumFlingVelocity: number = 50;
  private static mMaximumFlingVelocity: number= 8000;
  public static DEG2RAD: number = (Math.PI / 180.0);
  public static FDEG2RAD: number = Math.PI / 180.;
  public static DOUBLE_EPSILON: number = 4.9E-324;
  public static FLOAT_EPSILON: number = 1.4E-45;

/**
     * initialize method, called inside the Chart.init() method.
     *
     * @param context
     */
  public static init() {

    //        if (context == null) {
    //            // noinspection deprecation
    //            mMinimumFlingVelocity = ViewConfiguration.getMinimumFlingVelocity();
    //            // noinspection deprecation
    //            mMaximumFlingVelocity = ViewConfiguration.getMaximumFlingVelocity();
    //
    //            Log.e("MPChartLib-Utils"
    //                    , "Utils.init(...) PROVIDED CONTEXT OBJECT IS NULL");
    //
    //        } else {
    //            ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
    //            mMinimumFlingVelocity = viewConfiguration.getScaledMinimumFlingVelocity();
    //            mMaximumFlingVelocity = viewConfiguration.getScaledMaximumFlingVelocity();
    //
    //            Resources res = context.getResources();
    //            mMetrics = res.getDisplayMetrics();
    //        }
  }


/**
  * This method converts dp unit to equivalent pixels, depending on device
  * density. NEEDS UTILS TO BE INITIALIZED BEFORE USAGE.
  *
  * @param dp A value in dp (density independent pixels) unit. Which we need
  *           to convert into pixels
  * @return A float value to represent px equivalent to dp depending on
  * device density
  */
  public static convertDpToPixel(dp: number): number{
    //return dp * this.scaledDensity;
    return vp2px(dp);
  }

  public static setScaledDensity(value: number) {
    this.scaledDensity = value
  }

//
//    /**
//     * This method converts device specific pixels to density independent
//     * pixels. NEEDS UTILS TO BE INITIALIZED BEFORE USAGE.
//     *
//     * @param px A value in px (pixels) unit. Which we need to convert into db
//     * @return A float value to represent dp equivalent to px value
//     */
//    public static float convertPixelsToDp(float px) {
//
//        if (mMetrics == null) {
//
//            Log.e("MPChartLib-Utils",
//                    "Utils NOT INITIALIZED. You need to call Utils.init(...) at least once before" +
//                            " calling Utils.convertPixelsToDp(...). Otherwise conversion does not" +
//                            " take place.");
//            return px;
//        }
//
//        return px / mMetrics.density;
//    }
//
/**
     * calculates the approximate width of a text, depending on a demo text
     * avoid repeated calls (e.g. inside drawing methods)
     *
     * @param paint
     * @param demoText
     * @return
     */
  public static calcTextWidth(paint: Paint, demoText: string):number{
    return demoText.length * paint.getTextSize() / 2;
  }

  private static mCalcTextHeightRect: MyRect = new MyRect();
/**
     * calculates the approximate height of a text, depending on a demo text
     * avoid repeated calls (e.g. inside drawing methods)
     *
     * @param paint
     * @param demoText
     * @return
     */
  public static calcTextHeight(paint: Paint, demoText: string): number {
    return paint.getTextSize();
  }

//    private static Paint.FontMetrics mFontMetrics = new Paint.FontMetrics();
//
//    public static getLineHeight(paint : Paint) :  number {
//        return getLineHeight(paint, mFontMetrics);
//    }

  public static getLineHeight(paint: Paint): number {
    //        paint.getFontMetrics(fontMetrics);
    ////        return fontMetrics.descent - fontMetrics.ascent;
    return paint.getTextSize();
  }
//
  public static getLineSpacing(paint: Paint): number {
    return 1.2;
  }
//
//    public static float getLineSpacing(Paint paint, Paint.FontMetrics fontMetrics){
//        paint.getFontMetrics(fontMetrics);
//        return fontMetrics.ascent - fontMetrics.top + fontMetrics.bottom;
//    }
//
//    /**
//     * Returns a recyclable FSize instance.
//     * calculates the approximate size of a text, depending on a demo text
//     * avoid repeated calls (e.g. inside drawing methods)
//     *
//     * @param paint
//     * @param demoText
//     * @return A Recyclable FSize instance
//     */
  public static calcTextSize(paint: Paint, demoText: string): FSize{
    var fsize: FSize = new FSize(paint.getTextSize() * demoText.length, paint.getTextSize());
    return fsize;
  }
//
//    private static Rect mCalcTextSizeRect = new Rect();
//    /**
//     * calculates the approximate size of a text, depending on a demo text
//     * avoid repeated calls (e.g. inside drawing methods)
//     *
//     * @param paint
//     * @param demoText
//     * @param outputFSize An output variable, modified by the function.
//     */
//    public static void calcTextSize(Paint paint, String demoText, FSize outputFSize) {
//
//        Rect r = mCalcTextSizeRect;
//        r.set(0,0,0,0);
//        paint.getTextBounds(demoText, 0, demoText.length(), r);
//        outputFSize.width = r.width();
//        outputFSize.height = r.height();
//
//    }
//
//
//    /**
//     * Math.pow(...) is very expensive, so avoid calling it and create it
//     * yourself.
//     */
//    private static final int POW_10[] = {
//            1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000
//    };
//
  private static mDefaultValueFormatter: IValueFormatter = Utils.generateDefaultValueFormatter();
//
  private static generateDefaultValueFormatter(): IValueFormatter {
    var formatter: DefaultValueFormatter = new DefaultValueFormatter(1);
    return formatter;
  }

//    /// - returns: The default value formatter used for all chart components that needs a default
  public static getDefaultValueFormatter(): IValueFormatter
  {
    return Utils.mDefaultValueFormatter;
  }
//
//    /**
//     * Formats the given number to the given number of decimals, and returns the
//     * number as a string, maximum 35 characters. If thousands are separated, the separating
//     * character is a dot (".").
//     *
//     * @param number
//     * @param digitCount
//     * @param separateThousands set this to true to separate thousands values
//     * @return
//     */
//    public static String formatNumber(float number, int digitCount, boolean separateThousands) {
//        return formatNumber(number, digitCount, separateThousands, '.');
//    }
//
//    /**
//     * Formats the given number to the given number of decimals, and returns the
//     * number as a string, maximum 35 characters.
//     *
//     * @param number
//     * @param digitCount
//     * @param separateThousands set this to true to separate thousands values
//     * @param separateChar      a caracter to be paced between the "thousands"
//     * @return
//     */
//    public static String formatNumber(float number, int digitCount, boolean separateThousands,
//                                      char separateChar) {
//
//        char[] out = new char[35];
//
//        boolean neg = false;
//        if (number == 0) {
//            return "0";
//        }
//
//        boolean zero = false;
//        if (number < 1 && number > -1) {
//            zero = true;
//        }
//
//        if (number < 0) {
//            neg = true;
//            number = -number;
//        }
//
//        if (digitCount > POW_10.length) {
//            digitCount = POW_10.length - 1;
//        }
//
//        number *= POW_10[digitCount];
//        long lval = Math.round(number);
//        int ind = out.length - 1;
//        int charCount = 0;
//        boolean decimalPointAdded = false;
//
//        while (lval != 0 || charCount < (digitCount + 1)) {
//            int digit = (int) (lval % 10);
//            lval = lval / 10;
//            out[ind--] = (char) (digit + '0');
//            charCount++;
//
//            // add decimal point
//            if (charCount == digitCount) {
//                out[ind--] = ',';
//                charCount++;
//                decimalPointAdded = true;
//
//                // add thousand separators
//            } else if (separateThousands && lval != 0 && charCount > digitCount) {
//
//                if (decimalPointAdded) {
//
//                    if ((charCount - digitCount) % 4 == 0) {
//                        out[ind--] = separateChar;
//                        charCount++;
//                    }
//
//                } else {
//
//                    if ((charCount - digitCount) % 4 == 3) {
//                        out[ind--] = separateChar;
//                        charCount++;
//                    }
//                }
//            }
//        }
//
//        // if number around zero (between 1 and -1)
//        if (zero) {
//            out[ind--] = '0';
//            charCount += 1;
//        }
//
//        // if the number is negative
//        if (neg) {
//            out[ind--] = '-';
//            charCount += 1;
//        }
//
//        int start = out.length - charCount;
//
//        return String.valueOf(out, start, out.length - start);
//    }
//
/**
     * rounds the given number to the next significant number
     *
     * @param number
     * @return
     */
  public static roundToNextSignificant(number: number): number {
    if (number == Infinity ||
    isNaN(number) ||
    number == 0.0)
    return 0;

    const d: number = Math.ceil(Math.log10(number < 0 ? -number : number));
    const pw: number = 1 - Math.floor(d);
    const magnitude: number = Math.pow(10, pw);
    const shifted: number = Math.round(number * magnitude);
    return shifted / magnitude;
  }

/**
  * Returns the appropriate number of decimals to be used for the provided
  * number.
  *
  * @param number
  * @return
  */
  public static getDecimals(number: number): number {

    let i: number = this.roundToNextSignificant(number);

    if (i == Infinity)
    return 0;

    return Math.floor(Math.ceil(-Math.log10(i)) + 2);
  }
//
//    /**
//     * Converts the provided Integer List to an int array.
//     *
//     * @param integers
//     * @return
//     */
//    public static int[] convertIntegers(List<Integer> integers) {
//
//        int[] ret = new int[integers.size()];
//
//        copyIntegers(integers, ret);
//
//        return ret;
//    }
//
//    public static void copyIntegers(List<Integer> from, int[] to){
//        int count = to.length < from.size() ? to.length : from.size();
//        for(int i = 0 ; i < count ; i++){
//            to[i] = from.get(i);
//        }
//    }
//
//    /**
//     * Converts the provided String List to a String array.
//     *
//     * @param strings
//     * @return
//     */
//    public static String[] convertStrings(List<String> strings) {
//
//        String[] ret = new String[strings.size()];
//
//        for (int i = 0; i < ret.length; i++) {
//            ret[i] = strings.get(i);
//        }
//
//        return ret;
//    }
//
//    public static void copyStrings(List<String> from, String[] to){
//        int count = to.length < from.size() ? to.length : from.size();
//        for(int i = 0 ; i < count ; i++){
//            to[i] = from.get(i);
//        }
//    }
//
/**
     * Replacement for the Math.nextUp(...) method that is only available in
     * HONEYCOMB and higher. Dat's some seeeeek sheeet.
     *
     * @param d
     * @return
     */
  public static nextUp(d: number): number {
    if (d == Infinity)
    return d;
    else {
      d += 0.0;
      return d >= 0.0 ? d += 0.000000001 : d -= 0.000000001;
    }
  }
//
//    /**
//     * Returns a recyclable MPPointF instance.
//     * Calculates the position around a center point, depending on the distance
//     * from the center, and the angle of the position around the center.
//     *
//     * @param center
//     * @param dist
//     * @param angle  in degrees, converted to radians internally
//     * @return
//     */

  public static getPosition(center:MPPointF,dist:number, angle:number, outputPoint?:MPPointF):MPPointF{
    let p:MPPointF = ((outputPoint==null||outputPoint==undefined)?MPPointF.getInstance(0,0):outputPoint);
    p.x = center.x + dist * Math.cos((angle* Math.PI / 180));
    p.y = center.y + dist * Math.sin((angle* Math.PI / 180));
    return p
  }
//
//    public static void velocityTrackerPointerUpCleanUpIfNecessary(MotionEvent ev,
//                                                                  VelocityTracker tracker) {
//
//        // Check the dot product of current velocities.
//        // If the pointer that left was opposing another velocity vector, clear.
//        tracker.computeCurrentVelocity(1000, mMaximumFlingVelocity);
//        final int upIndex = ev.getActionIndex();
//        final int id1 = ev.getPointerId(upIndex);
//        final float x1 = tracker.getXVelocity(id1);
//        final float y1 = tracker.getYVelocity(id1);
//        for (int i = 0, count = ev.getPointerCount(); i < count; i++) {
//            if (i == upIndex)
//                continue;
//
//            final int id2 = ev.getPointerId(i);
//            final float x = x1 * tracker.getXVelocity(id2);
//            final float y = y1 * tracker.getYVelocity(id2);
//
//            final float dot = x + y;
//            if (dot < 0) {
//                tracker.clear();
//                break;
//            }
//        }
//    }
//
//    /**
//     * Original method view.postInvalidateOnAnimation() only supportd in API >=
//     * 16, This is a replica of the code from ViewCompat.
//     *
//     * @param view
//     */
//    @SuppressLint("NewApi")
//    public static void postInvalidateOnAnimation(View view) {
//        if (Build.VERSION.SDK_INT >= 16)
//            view.postInvalidateOnAnimation();
//        else
//            view.postInvalidateDelayed(10);
//    }
//
  public static getMinimumFlingVelocity():number {
    return Utils.mMinimumFlingVelocity;
  }
//
//    public static int getMaximumFlingVelocity() {
//        return mMaximumFlingVelocity;
//    }
//
    /**
     * returns an angle between 0.f < 360.f (not less than zero, less than 360)
     */
    public static getNormalizedAngle(angle:number):number {
        while (angle < 0)
            angle += 360;

        return angle % 360;
    }

  private static mDrawableBoundsCache: MyRect = new MyRect();

  public static drawImage(icon: string|Resource,x: number, y: number,
                          width: number, height: number): Paint[] {

    let drawOffset: MPPointF = MPPointF.getInstance();
    drawOffset.x = x - (width / 2);
    drawOffset.y = y - (height / 2);

    let drawable:ImagePaint = new ImagePaint();
    drawable.setX(this.mDrawableBoundsCache.left);
    drawable.setY(this.mDrawableBoundsCache.top);
    drawable.setWidth(width);
    drawable.setHeight(width);
    drawable.setIcon(icon)

    drawable.setX(drawable.x + drawOffset.x);
    drawable.setY(drawable.y + drawOffset.y);
    return [drawable];
  }

//    private static Rect mDrawTextRectBuffer = new Rect();
//    private static Paint.FontMetrics mFontMetricsBuffer = new Paint.FontMetrics();
//
  public static drawXAxisValue(text: string, x: number, y: number, paint: TextPaint,
                               anchor: MPPointF, angleDegrees: number): Paint{

    var drawOffsetX: number = 0;
    var drawOffsetY: number = 0;

    var labelSize: FSize = Utils.calcTextSize(paint, text);

    drawOffsetX -= labelSize.width;

    //  and draws from bottom to top.
    // And we want to normalize it.
    drawOffsetY += -labelSize.height;

    // To have a consistent point of reference, we always draw left-aligned
    paint.setTextAlign(TextAlign.Start);
    paint.setText(text)
    if (angleDegrees != 0) {

      // Move the text drawing rect in a way that it always rotates around its center
      drawOffsetX -= labelSize.width * 0.5;
      drawOffsetY -= labelSize.height * 0.5;

      var translateX: number = x;
      var translateY: number = y;

      // Move the "outer" rect relative to the anchor, assuming its centered
      if (anchor.x != 0.5 || anchor.y != 0.5) {
        var rotatedSize: FSize = Utils.getSizeOfRotatedRectangleByDegrees(
          labelSize.width,
          labelSize.height,
          angleDegrees);

        translateX -= rotatedSize.width * (anchor.x - 0.5);
        translateY -= rotatedSize.height * (anchor.y - 0.5);
        FSize.recycleInstance(rotatedSize);
      }
      paint.setTranslateX(translateX)
      paint.setTranslateY(translateY)
      paint.setRotate(angleDegrees)
      paint.setX(drawOffsetX);
      paint.setY(drawOffsetY);
    } else {
        if (anchor.x != 0 || anchor.y != 0) {
          drawOffsetX = labelSize.width / 2 * anchor.x;
          drawOffsetY = 12 * anchor.y;
        }
        x -= drawOffsetX;
        y -= drawOffsetY;
        paint.setX(x);
        paint.setY(y);
    }
    return paint
  }
//
//    public static void drawMultilineText(Canvas c, StaticLayout textLayout,
//                                         float x, float y,
//                                         TextPaint paint,
//                                         MPPointF anchor, float angleDegrees) {
//
//        float drawOffsetX = 0.f;
//        float drawOffsetY = 0.f;
//        float drawWidth;
//        float drawHeight;
//
//        final float lineHeight = paint.getFontMetrics(mFontMetricsBuffer);
//
//        drawWidth = textLayout.getWidth();
//        drawHeight = textLayout.getLineCount() * lineHeight;
//
//        drawOffsetX -= mDrawTextRectBuffer.left;
//
//        //  and draws from bottom to top.
//        // And we want to normalize it.
//        drawOffsetY += drawHeight;
//
//        // To have a consistent point of reference, we always draw left-aligned
//        Paint.Align originalTextAlign = paint.getTextAlign();
//        paint.setTextAlign(Paint.Align.LEFT);
//
//        if (angleDegrees != 0.f) {
//
//            // Move the text drawing rect in a way that it always rotates around its center
//            drawOffsetX -= drawWidth * 0.5f;
//            drawOffsetY -= drawHeight * 0.5f;
//
//            float translateX = x;
//            float translateY = y;
//
//            // Move the "outer" rect relative to the anchor, assuming its centered
//            if (anchor.x != 0.5f || anchor.y != 0.5f) {
//                final FSize rotatedSize = getSizeOfRotatedRectangleByDegrees(
//                        drawWidth,
//                        drawHeight,
//                        angleDegrees);
//
//                translateX -= rotatedSize.width * (anchor.x - 0.5f);
//                translateY -= rotatedSize.height * (anchor.y - 0.5f);
//                FSize.recycleInstance(rotatedSize);
//            }
//
//            c.save();
//            c.translate(translateX, translateY);
//            c.rotate(angleDegrees);
//
//            c.translate(drawOffsetX, drawOffsetY);
//            textLayout.draw(c);
//
//            c.restore();
//        } else {
//            if (anchor.x != 0.f || anchor.y != 0.f) {
//
//                drawOffsetX -= drawWidth * anchor.x;
//                drawOffsetY -= drawHeight * anchor.y;
//            }
//
//            drawOffsetX += x;
//            drawOffsetY += y;
//
//            c.save();
//
//            c.translate(drawOffsetX, drawOffsetY);
//            textLayout.draw(c);
//
//            c.restore();
//        }
//
//        paint.setTextAlign(originalTextAlign);
//    }
//
//    public static void drawMultilineText(Canvas c, String text,
//                                         float x, float y,
//                                         TextPaint paint,
//                                         FSize constrainedToSize,
//                                         MPPointF anchor, float angleDegrees) {
//
//        StaticLayout textLayout = new StaticLayout(
//                text, 0, text.length(),
//                paint,
//                (int) Math.max(Math.ceil(constrainedToSize.width), 1.f),
//                Layout.Alignment.ALIGN_NORMAL, 1.f, 0.f, false);
//
//
//        drawMultilineText(c, textLayout, x, y, paint, anchor, angleDegrees);
//    }
//
//    /**
//     * Returns a recyclable FSize instance.
//     * Represents size of a rotated rectangle by degrees.
//     *
//     * @param rectangleSize
//     * @param degrees
//     * @return A Recyclable FSize instance
//     */
//    public static getSizeOfRotatedRectangleByDegrees( rectangleSize:FSize, degrees:number):FSize{
//        var radians:number = degrees * Utils.FDEG2RAD;
//        return this.getSizeOfRotatedRectangleByRadians(rectangleSize.width, rectangleSize.height,
//                radians);
//    }
//
//    /**
//     * Returns a recyclable FSize instance.
//     * Represents size of a rotated rectangle by radians.
//     *
//     * @param rectangleSize
//     * @param radians
//     * @return A Recyclable FSize instance
//     */
//    public static  getSizeOfRotatedRectangleByRadians( rectangleSize:FSize,  radians:number):FSize {
//        return getSizeOfRotatedRectangleByRadians(rectangleSize.width, rectangleSize.height,
//                radians);
//    }
//
//    /**
//     * Returns a recyclable FSize instance.
//     * Represents size of a rotated rectangle by degrees.
//     *
//     * @param rectangleWidth
//     * @param rectangleHeight
//     * @param degrees
//     * @return A Recyclable FSize instance
//     */
  public static getSizeOfRotatedRectangleByDegrees(rectangleWidth: number,
                                                   rectangleHeight: number, degrees: number): FSize{
    var radians: number = degrees * Utils.FDEG2RAD;
    return Utils.getSizeOfRotatedRectangleByRadians(rectangleWidth, rectangleHeight, radians);
  }
//
//    /**
//     * Returns a recyclable FSize instance.
//     * Represents size of a rotated rectangle by radians.
//     *
//     * @param rectangleWidth
//     * @param rectangleHeight
//     * @param radians
//     * @return A Recyclable FSize instance
//     */
  public static getSizeOfRotatedRectangleByRadians(rectangleWidth: number,
                                                   rectangleHeight: number, radians: number): FSize{
    return FSize.getInstance(
      Math.abs(rectangleWidth * Math.cos(radians)) + Math.abs(rectangleHeight *
      Math.sin(radians)),
      Math.abs(rectangleWidth * Math.sin(radians)) + Math.abs(rectangleHeight *
      Math.cos(radians))
    );
  }

  public static getSDKInt():number {
    return deviceInfo.sdkApiVersion;
  }
}
