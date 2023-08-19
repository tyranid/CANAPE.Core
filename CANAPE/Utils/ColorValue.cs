//    CANAPE Core Network Testing Library
//    Copyright (C) 2017 James Forshaw
//    Based in part on CANAPE Network Testing Tool
//    Copyright (C) 2014 Context Information Security
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
using System;
using System.Globalization;
using System.Reflection;

namespace CANAPE.Utils
{
    /// <summary>
    /// This structure is used to hold a 32bit colour, makes us independant of System.Drawing
    /// </summary>
    public struct ColorValue
    {
        /// <summary>
        /// Red
        /// </summary>
        public byte R;
        /// <summary>
        /// Green
        /// </summary>
        public byte G;
        /// <summary>
        /// Blue
        /// </summary>
        public byte B;
        /// <summary>
        /// Alpha
        /// </summary>
        public byte A;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="r">Red value</param>
        /// <param name="g">Green value</param>
        /// <param name="b">Blue value</param>
        /// <param name="a">Alpha value</param>
        public ColorValue(byte r, byte g, byte b, byte a)
        {
            R = r;
            G = g;
            B = b;
            A = a;
        }

        /// <summary>
        /// Constructor, set color values with maximum alpha
        /// </summary>
        /// <param name="r">Red value</param>
        /// <param name="g">Green value</param>
        /// <param name="b">Blue value</param>
        public ColorValue(byte r, byte g, byte b)
            : this(r, g, b, 255)
        {
        }

        /// <summary>
        /// Equality operator
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator ==(
            ColorValue left,
            ColorValue right
        )
        {
            return (left.R == right.R) && (left.G == right.G) && (left.B == right.B) && (left.A == right.A);
        }

        /// <summary>
        /// Inequality operator
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator !=(
            ColorValue left,
            ColorValue right
        )
        {
            return !(left == right);
        }

        /// <summary>
        /// Equals method
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (obj is ColorValue)
            {
                return this == (ColorValue)obj;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Hashcode method
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return R | G << 8 | B << 16 | A << 24;
        }

        private string FindName()
        {
            foreach (PropertyInfo pi in typeof(ColorValue).GetTypeInfo().GetProperties(BindingFlags.Public | BindingFlags.Static))
            {
                if (pi.GetValue(null, null).Equals(this))
                {
                    return pi.Name;
                }
            }

            return null;
        }

        private static bool FindColor(string name, out ColorValue cv)
        {
            cv = new ColorValue();

            foreach (PropertyInfo pi in typeof(ColorValue).GetTypeInfo().GetProperties(BindingFlags.Public | BindingFlags.Static))
            {
                if (pi.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    cv = (ColorValue)pi.GetValue(null, null);

                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// To String 
        /// </summary>
        /// <returns>Converts to a string</returns>
        public override string ToString()
        {
            string name = FindName();

            if (name == null)
            {
                name = String.Format("#{0:X02}{1:X02}{2:X02}", R, G, B);
            }

            return name;
        }

        private static bool ParseHex(string s, int index, out byte v)
        {
            return byte.TryParse(s.Substring(index + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v);
        }

        /// <summary>
        /// Try parsing the string
        /// </summary>
        /// <param name="str">The string to parse, should be in form of #RRGGBB where values are hex or an X11 color name</param>
        /// <param name="color">The output color value</param>
        /// <returns>True if could parse the string</returns>
        public static bool TryParse(string str, out ColorValue color)
        {
            bool ret = false;

            str = str.Trim();

            color = new ColorValue();

            if (str.StartsWith("#") && (str.Length == 7))
            {
                byte r = 0;
                byte g = 0;
                byte b = 0;

                if (ParseHex(str, 0, out r) && ParseHex(str, 2, out g) && ParseHex(str, 4, out b))
                {
                    color = new ColorValue(r, g, b);
                    ret = true;
                }
            }
            else
            {
                ret = FindColor(str, out color);
            }

            return ret;
        }

        /// <summary>
        /// Parse a string
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static ColorValue Parse(string str)
        {
            ColorValue color;

            if (!TryParse(str, out color))
            {
                throw new FormatException(Properties.Resources.ColorValue_InvalidStringFormat);
            }

            return color;
        }

        /// <summary>
        /// X11 Color Snow (255,250,250)
        /// </summary>
        public static ColorValue Snow { get { return new ColorValue(255, 250, 250); } }

        /// <summary>
        /// X11 Color Ghostwhite (248,248,255)
        /// </summary>
        public static ColorValue Ghostwhite { get { return new ColorValue(248, 248, 255); } }

        /// <summary>
        /// X11 Color Whitesmoke (245,245,245)
        /// </summary>
        public static ColorValue Whitesmoke { get { return new ColorValue(245, 245, 245); } }

        /// <summary>
        /// X11 Color Gainsboro (220,220,220)
        /// </summary>
        public static ColorValue Gainsboro { get { return new ColorValue(220, 220, 220); } }

        /// <summary>
        /// X11 Color Floralwhite (255,250,240)
        /// </summary>
        public static ColorValue Floralwhite { get { return new ColorValue(255, 250, 240); } }

        /// <summary>
        /// X11 Color Oldlace (253,245,230)
        /// </summary>
        public static ColorValue Oldlace { get { return new ColorValue(253, 245, 230); } }

        /// <summary>
        /// X11 Color Linen (250,240,230)
        /// </summary>
        public static ColorValue Linen { get { return new ColorValue(250, 240, 230); } }

        /// <summary>
        /// X11 Color Antiquewhite (250,235,215)
        /// </summary>
        public static ColorValue Antiquewhite { get { return new ColorValue(250, 235, 215); } }

        /// <summary>
        /// X11 Color Papayawhip (255,239,213)
        /// </summary>
        public static ColorValue Papayawhip { get { return new ColorValue(255, 239, 213); } }

        /// <summary>
        /// X11 Color Blanchedalmond (255,235,205)
        /// </summary>
        public static ColorValue Blanchedalmond { get { return new ColorValue(255, 235, 205); } }

        /// <summary>
        /// X11 Color Bisque (255,228,196)
        /// </summary>
        public static ColorValue Bisque { get { return new ColorValue(255, 228, 196); } }

        /// <summary>
        /// X11 Color Peachpuff (255,218,185)
        /// </summary>
        public static ColorValue Peachpuff { get { return new ColorValue(255, 218, 185); } }

        /// <summary>
        /// X11 Color Navajowhite (255,222,173)
        /// </summary>
        public static ColorValue Navajowhite { get { return new ColorValue(255, 222, 173); } }

        /// <summary>
        /// X11 Color Moccasin (255,228,181)
        /// </summary>
        public static ColorValue Moccasin { get { return new ColorValue(255, 228, 181); } }

        /// <summary>
        /// X11 Color Cornsilk (255,248,220)
        /// </summary>
        public static ColorValue Cornsilk { get { return new ColorValue(255, 248, 220); } }

        /// <summary>
        /// X11 Color Ivory (255,255,240)
        /// </summary>
        public static ColorValue Ivory { get { return new ColorValue(255, 255, 240); } }

        /// <summary>
        /// X11 Color Lemonchiffon (255,250,205)
        /// </summary>
        public static ColorValue Lemonchiffon { get { return new ColorValue(255, 250, 205); } }

        /// <summary>
        /// X11 Color Seashell (255,245,238)
        /// </summary>
        public static ColorValue Seashell { get { return new ColorValue(255, 245, 238); } }

        /// <summary>
        /// X11 Color Honeydew (240,255,240)
        /// </summary>
        public static ColorValue Honeydew { get { return new ColorValue(240, 255, 240); } }

        /// <summary>
        /// X11 Color Mintcream (245,255,250)
        /// </summary>
        public static ColorValue Mintcream { get { return new ColorValue(245, 255, 250); } }

        /// <summary>
        /// X11 Color Azure (240,255,255)
        /// </summary>
        public static ColorValue Azure { get { return new ColorValue(240, 255, 255); } }

        /// <summary>
        /// X11 Color Aliceblue (240,248,255)
        /// </summary>
        public static ColorValue Aliceblue { get { return new ColorValue(240, 248, 255); } }

        /// <summary>
        /// X11 Color Lavender (230,230,250)
        /// </summary>
        public static ColorValue Lavender { get { return new ColorValue(230, 230, 250); } }

        /// <summary>
        /// X11 Color Lavenderblush (255,240,245)
        /// </summary>
        public static ColorValue Lavenderblush { get { return new ColorValue(255, 240, 245); } }

        /// <summary>
        /// X11 Color Mistyrose (255,228,225)
        /// </summary>
        public static ColorValue Mistyrose { get { return new ColorValue(255, 228, 225); } }

        /// <summary>
        /// X11 Color White (255,255,255)
        /// </summary>
        public static ColorValue White { get { return new ColorValue(255, 255, 255); } }

        /// <summary>
        /// X11 Color Black (0,0,0)
        /// </summary>
        public static ColorValue Black { get { return new ColorValue(0, 0, 0); } }

        /// <summary>
        /// X11 Color Darkslategray (47,79,79)
        /// </summary>
        public static ColorValue Darkslategray { get { return new ColorValue(47, 79, 79); } }

        /// <summary>
        /// X11 Color Darkslategrey (47,79,79)
        /// </summary>
        public static ColorValue Darkslategrey { get { return new ColorValue(47, 79, 79); } }

        /// <summary>
        /// X11 Color Dimgray (105,105,105)
        /// </summary>
        public static ColorValue Dimgray { get { return new ColorValue(105, 105, 105); } }

        /// <summary>
        /// X11 Color Dimgrey (105,105,105)
        /// </summary>
        public static ColorValue Dimgrey { get { return new ColorValue(105, 105, 105); } }

        /// <summary>
        /// X11 Color Slategray (112,128,144)
        /// </summary>
        public static ColorValue Slategray { get { return new ColorValue(112, 128, 144); } }

        /// <summary>
        /// X11 Color Slategrey (112,128,144)
        /// </summary>
        public static ColorValue Slategrey { get { return new ColorValue(112, 128, 144); } }

        /// <summary>
        /// X11 Color Lightslategray (119,136,153)
        /// </summary>
        public static ColorValue Lightslategray { get { return new ColorValue(119, 136, 153); } }

        /// <summary>
        /// X11 Color Lightslategrey (119,136,153)
        /// </summary>
        public static ColorValue Lightslategrey { get { return new ColorValue(119, 136, 153); } }

        /// <summary>
        /// X11 Color Gray (190,190,190)
        /// </summary>
        public static ColorValue Gray { get { return new ColorValue(190, 190, 190); } }

        /// <summary>
        /// X11 Color Grey (190,190,190)
        /// </summary>
        public static ColorValue Grey { get { return new ColorValue(190, 190, 190); } }

        /// <summary>
        /// X11 Color Lightgrey (211,211,211)
        /// </summary>
        public static ColorValue Lightgrey { get { return new ColorValue(211, 211, 211); } }

        /// <summary>
        /// X11 Color Lightgray (211,211,211)
        /// </summary>
        public static ColorValue Lightgray { get { return new ColorValue(211, 211, 211); } }

        /// <summary>
        /// X11 Color Midnightblue (25,25,112)
        /// </summary>
        public static ColorValue Midnightblue { get { return new ColorValue(25, 25, 112); } }

        /// <summary>
        /// X11 Color Navy (0,0,128)
        /// </summary>
        public static ColorValue Navy { get { return new ColorValue(0, 0, 128); } }

        /// <summary>
        /// X11 Color Navyblue (0,0,128)
        /// </summary>
        public static ColorValue Navyblue { get { return new ColorValue(0, 0, 128); } }

        /// <summary>
        /// X11 Color Cornflowerblue (100,149,237)
        /// </summary>
        public static ColorValue Cornflowerblue { get { return new ColorValue(100, 149, 237); } }

        /// <summary>
        /// X11 Color Darkslateblue (72,61,139)
        /// </summary>
        public static ColorValue Darkslateblue { get { return new ColorValue(72, 61, 139); } }

        /// <summary>
        /// X11 Color Slateblue (106,90,205)
        /// </summary>
        public static ColorValue Slateblue { get { return new ColorValue(106, 90, 205); } }

        /// <summary>
        /// X11 Color Mediumslateblue (123,104,238)
        /// </summary>
        public static ColorValue Mediumslateblue { get { return new ColorValue(123, 104, 238); } }

        /// <summary>
        /// X11 Color Lightslateblue (132,112,255)
        /// </summary>
        public static ColorValue Lightslateblue { get { return new ColorValue(132, 112, 255); } }

        /// <summary>
        /// X11 Color Mediumblue (0,0,205)
        /// </summary>
        public static ColorValue Mediumblue { get { return new ColorValue(0, 0, 205); } }

        /// <summary>
        /// X11 Color Royalblue (65,105,225)
        /// </summary>
        public static ColorValue Royalblue { get { return new ColorValue(65, 105, 225); } }

        /// <summary>
        /// X11 Color Blue (0,0,255)
        /// </summary>
        public static ColorValue Blue { get { return new ColorValue(0, 0, 255); } }

        /// <summary>
        /// X11 Color Dodgerblue (30,144,255)
        /// </summary>
        public static ColorValue Dodgerblue { get { return new ColorValue(30, 144, 255); } }

        /// <summary>
        /// X11 Color Deepskyblue (0,191,255)
        /// </summary>
        public static ColorValue Deepskyblue { get { return new ColorValue(0, 191, 255); } }

        /// <summary>
        /// X11 Color Skyblue (135,206,235)
        /// </summary>
        public static ColorValue Skyblue { get { return new ColorValue(135, 206, 235); } }

        /// <summary>
        /// X11 Color Lightskyblue (135,206,250)
        /// </summary>
        public static ColorValue Lightskyblue { get { return new ColorValue(135, 206, 250); } }

        /// <summary>
        /// X11 Color Steelblue (70,130,180)
        /// </summary>
        public static ColorValue Steelblue { get { return new ColorValue(70, 130, 180); } }

        /// <summary>
        /// X11 Color Lightsteelblue (176,196,222)
        /// </summary>
        public static ColorValue Lightsteelblue { get { return new ColorValue(176, 196, 222); } }

        /// <summary>
        /// X11 Color Lightblue (173,216,230)
        /// </summary>
        public static ColorValue Lightblue { get { return new ColorValue(173, 216, 230); } }

        /// <summary>
        /// X11 Color Powderblue (176,224,230)
        /// </summary>
        public static ColorValue Powderblue { get { return new ColorValue(176, 224, 230); } }

        /// <summary>
        /// X11 Color Paleturquoise (175,238,238)
        /// </summary>
        public static ColorValue Paleturquoise { get { return new ColorValue(175, 238, 238); } }

        /// <summary>
        /// X11 Color Darkturquoise (0,206,209)
        /// </summary>
        public static ColorValue Darkturquoise { get { return new ColorValue(0, 206, 209); } }

        /// <summary>
        /// X11 Color Mediumturquoise (72,209,204)
        /// </summary>
        public static ColorValue Mediumturquoise { get { return new ColorValue(72, 209, 204); } }

        /// <summary>
        /// X11 Color Turquoise (64,224,208)
        /// </summary>
        public static ColorValue Turquoise { get { return new ColorValue(64, 224, 208); } }

        /// <summary>
        /// X11 Color Cyan (0,255,255)
        /// </summary>
        public static ColorValue Cyan { get { return new ColorValue(0, 255, 255); } }

        /// <summary>
        /// X11 Color Lightcyan (224,255,255)
        /// </summary>
        public static ColorValue Lightcyan { get { return new ColorValue(224, 255, 255); } }

        /// <summary>
        /// X11 Color Cadetblue (95,158,160)
        /// </summary>
        public static ColorValue Cadetblue { get { return new ColorValue(95, 158, 160); } }

        /// <summary>
        /// X11 Color Mediumaquamarine (102,205,170)
        /// </summary>
        public static ColorValue Mediumaquamarine { get { return new ColorValue(102, 205, 170); } }

        /// <summary>
        /// X11 Color Aquamarine (127,255,212)
        /// </summary>
        public static ColorValue Aquamarine { get { return new ColorValue(127, 255, 212); } }

        /// <summary>
        /// X11 Color Darkgreen (0,100,0)
        /// </summary>
        public static ColorValue Darkgreen { get { return new ColorValue(0, 100, 0); } }

        /// <summary>
        /// X11 Color Darkolivegreen (85,107,47)
        /// </summary>
        public static ColorValue Darkolivegreen { get { return new ColorValue(85, 107, 47); } }

        /// <summary>
        /// X11 Color Darkseagreen (143,188,143)
        /// </summary>
        public static ColorValue Darkseagreen { get { return new ColorValue(143, 188, 143); } }

        /// <summary>
        /// X11 Color Seagreen (46,139,87)
        /// </summary>
        public static ColorValue Seagreen { get { return new ColorValue(46, 139, 87); } }

        /// <summary>
        /// X11 Color Mediumseagreen (60,179,113)
        /// </summary>
        public static ColorValue Mediumseagreen { get { return new ColorValue(60, 179, 113); } }

        /// <summary>
        /// X11 Color Lightseagreen (32,178,170)
        /// </summary>
        public static ColorValue Lightseagreen { get { return new ColorValue(32, 178, 170); } }

        /// <summary>
        /// X11 Color Palegreen (152,251,152)
        /// </summary>
        public static ColorValue Palegreen { get { return new ColorValue(152, 251, 152); } }

        /// <summary>
        /// X11 Color Springgreen (0,255,127)
        /// </summary>
        public static ColorValue Springgreen { get { return new ColorValue(0, 255, 127); } }

        /// <summary>
        /// X11 Color Lawngreen (124,252,0)
        /// </summary>
        public static ColorValue Lawngreen { get { return new ColorValue(124, 252, 0); } }

        /// <summary>
        /// X11 Color Green (0,255,0)
        /// </summary>
        public static ColorValue Green { get { return new ColorValue(0, 255, 0); } }

        /// <summary>
        /// X11 Color Chartreuse (127,255,0)
        /// </summary>
        public static ColorValue Chartreuse { get { return new ColorValue(127, 255, 0); } }

        /// <summary>
        /// X11 Color Mediumspringgreen (0,250,154)
        /// </summary>
        public static ColorValue Mediumspringgreen { get { return new ColorValue(0, 250, 154); } }

        /// <summary>
        /// X11 Color Greenyellow (173,255,47)
        /// </summary>
        public static ColorValue Greenyellow { get { return new ColorValue(173, 255, 47); } }

        /// <summary>
        /// X11 Color Limegreen (50,205,50)
        /// </summary>
        public static ColorValue Limegreen { get { return new ColorValue(50, 205, 50); } }

        /// <summary>
        /// X11 Color Yellowgreen (154,205,50)
        /// </summary>
        public static ColorValue Yellowgreen { get { return new ColorValue(154, 205, 50); } }

        /// <summary>
        /// X11 Color Forestgreen (34,139,34)
        /// </summary>
        public static ColorValue Forestgreen { get { return new ColorValue(34, 139, 34); } }

        /// <summary>
        /// X11 Color Olivedrab (107,142,35)
        /// </summary>
        public static ColorValue Olivedrab { get { return new ColorValue(107, 142, 35); } }

        /// <summary>
        /// X11 Color Darkkhaki (189,183,107)
        /// </summary>
        public static ColorValue Darkkhaki { get { return new ColorValue(189, 183, 107); } }

        /// <summary>
        /// X11 Color Khaki (240,230,140)
        /// </summary>
        public static ColorValue Khaki { get { return new ColorValue(240, 230, 140); } }

        /// <summary>
        /// X11 Color Palegoldenrod (238,232,170)
        /// </summary>
        public static ColorValue Palegoldenrod { get { return new ColorValue(238, 232, 170); } }

        /// <summary>
        /// X11 Color Lightgoldenrodyellow (250,250,210)
        /// </summary>
        public static ColorValue Lightgoldenrodyellow { get { return new ColorValue(250, 250, 210); } }

        /// <summary>
        /// X11 Color Lightyellow (255,255,224)
        /// </summary>
        public static ColorValue Lightyellow { get { return new ColorValue(255, 255, 224); } }

        /// <summary>
        /// X11 Color Yellow (255,255,0)
        /// </summary>
        public static ColorValue Yellow { get { return new ColorValue(255, 255, 0); } }

        /// <summary>
        /// X11 Color Gold (255,215,0)
        /// </summary>
        public static ColorValue Gold { get { return new ColorValue(255, 215, 0); } }

        /// <summary>
        /// X11 Color Lightgoldenrod (238,221,130)
        /// </summary>
        public static ColorValue Lightgoldenrod { get { return new ColorValue(238, 221, 130); } }

        /// <summary>
        /// X11 Color Goldenrod (218,165,32)
        /// </summary>
        public static ColorValue Goldenrod { get { return new ColorValue(218, 165, 32); } }

        /// <summary>
        /// X11 Color Darkgoldenrod (184,134,11)
        /// </summary>
        public static ColorValue Darkgoldenrod { get { return new ColorValue(184, 134, 11); } }

        /// <summary>
        /// X11 Color Rosybrown (188,143,143)
        /// </summary>
        public static ColorValue Rosybrown { get { return new ColorValue(188, 143, 143); } }

        /// <summary>
        /// X11 Color Indianred (205,92,92)
        /// </summary>
        public static ColorValue Indianred { get { return new ColorValue(205, 92, 92); } }

        /// <summary>
        /// X11 Color Saddlebrown (139,69,19)
        /// </summary>
        public static ColorValue Saddlebrown { get { return new ColorValue(139, 69, 19); } }

        /// <summary>
        /// X11 Color Sienna (160,82,45)
        /// </summary>
        public static ColorValue Sienna { get { return new ColorValue(160, 82, 45); } }

        /// <summary>
        /// X11 Color Peru (205,133,63)
        /// </summary>
        public static ColorValue Peru { get { return new ColorValue(205, 133, 63); } }

        /// <summary>
        /// X11 Color Burlywood (222,184,135)
        /// </summary>
        public static ColorValue Burlywood { get { return new ColorValue(222, 184, 135); } }

        /// <summary>
        /// X11 Color Beige (245,245,220)
        /// </summary>
        public static ColorValue Beige { get { return new ColorValue(245, 245, 220); } }

        /// <summary>
        /// X11 Color Wheat (245,222,179)
        /// </summary>
        public static ColorValue Wheat { get { return new ColorValue(245, 222, 179); } }

        /// <summary>
        /// X11 Color Sandybrown (244,164,96)
        /// </summary>
        public static ColorValue Sandybrown { get { return new ColorValue(244, 164, 96); } }

        /// <summary>
        /// X11 Color Tan (210,180,140)
        /// </summary>
        public static ColorValue Tan { get { return new ColorValue(210, 180, 140); } }

        /// <summary>
        /// X11 Color Chocolate (210,105,30)
        /// </summary>
        public static ColorValue Chocolate { get { return new ColorValue(210, 105, 30); } }

        /// <summary>
        /// X11 Color Firebrick (178,34,34)
        /// </summary>
        public static ColorValue Firebrick { get { return new ColorValue(178, 34, 34); } }

        /// <summary>
        /// X11 Color Brown (165,42,42)
        /// </summary>
        public static ColorValue Brown { get { return new ColorValue(165, 42, 42); } }

        /// <summary>
        /// X11 Color Darksalmon (233,150,122)
        /// </summary>
        public static ColorValue Darksalmon { get { return new ColorValue(233, 150, 122); } }

        /// <summary>
        /// X11 Color Salmon (250,128,114)
        /// </summary>
        public static ColorValue Salmon { get { return new ColorValue(250, 128, 114); } }

        /// <summary>
        /// X11 Color Lightsalmon (255,160,122)
        /// </summary>
        public static ColorValue Lightsalmon { get { return new ColorValue(255, 160, 122); } }

        /// <summary>
        /// X11 Color Orange (255,165,0)
        /// </summary>
        public static ColorValue Orange { get { return new ColorValue(255, 165, 0); } }

        /// <summary>
        /// X11 Color Darkorange (255,140,0)
        /// </summary>
        public static ColorValue Darkorange { get { return new ColorValue(255, 140, 0); } }

        /// <summary>
        /// X11 Color Coral (255,127,80)
        /// </summary>
        public static ColorValue Coral { get { return new ColorValue(255, 127, 80); } }

        /// <summary>
        /// X11 Color Lightcoral (240,128,128)
        /// </summary>
        public static ColorValue Lightcoral { get { return new ColorValue(240, 128, 128); } }

        /// <summary>
        /// X11 Color Tomato (255,99,71)
        /// </summary>
        public static ColorValue Tomato { get { return new ColorValue(255, 99, 71); } }

        /// <summary>
        /// X11 Color Orangered (255,69,0)
        /// </summary>
        public static ColorValue Orangered { get { return new ColorValue(255, 69, 0); } }

        /// <summary>
        /// X11 Color Red (255,0,0)
        /// </summary>
        public static ColorValue Red { get { return new ColorValue(255, 0, 0); } }

        /// <summary>
        /// X11 Color Hotpink (255,105,180)
        /// </summary>
        public static ColorValue Hotpink { get { return new ColorValue(255, 105, 180); } }

        /// <summary>
        /// X11 Color Deeppink (255,20,147)
        /// </summary>
        public static ColorValue Deeppink { get { return new ColorValue(255, 20, 147); } }

        /// <summary>
        /// X11 Color Pink (255,192,203)
        /// </summary>
        public static ColorValue Pink { get { return new ColorValue(255, 192, 203); } }

        /// <summary>
        /// X11 Color Lightpink (255,182,193)
        /// </summary>
        public static ColorValue Lightpink { get { return new ColorValue(255, 182, 193); } }

        /// <summary>
        /// X11 Color Palevioletred (219,112,147)
        /// </summary>
        public static ColorValue Palevioletred { get { return new ColorValue(219, 112, 147); } }

        /// <summary>
        /// X11 Color Maroon (176,48,96)
        /// </summary>
        public static ColorValue Maroon { get { return new ColorValue(176, 48, 96); } }

        /// <summary>
        /// X11 Color Mediumvioletred (199,21,133)
        /// </summary>
        public static ColorValue Mediumvioletred { get { return new ColorValue(199, 21, 133); } }

        /// <summary>
        /// X11 Color Violetred (208,32,144)
        /// </summary>
        public static ColorValue Violetred { get { return new ColorValue(208, 32, 144); } }

        /// <summary>
        /// X11 Color Magenta (255,0,255)
        /// </summary>
        public static ColorValue Magenta { get { return new ColorValue(255, 0, 255); } }

        /// <summary>
        /// X11 Color Violet (238,130,238)
        /// </summary>
        public static ColorValue Violet { get { return new ColorValue(238, 130, 238); } }

        /// <summary>
        /// X11 Color Plum (221,160,221)
        /// </summary>
        public static ColorValue Plum { get { return new ColorValue(221, 160, 221); } }

        /// <summary>
        /// X11 Color Orchid (218,112,214)
        /// </summary>
        public static ColorValue Orchid { get { return new ColorValue(218, 112, 214); } }

        /// <summary>
        /// X11 Color Mediumorchid (186,85,211)
        /// </summary>
        public static ColorValue Mediumorchid { get { return new ColorValue(186, 85, 211); } }

        /// <summary>
        /// X11 Color Darkorchid (153,50,204)
        /// </summary>
        public static ColorValue Darkorchid { get { return new ColorValue(153, 50, 204); } }

        /// <summary>
        /// X11 Color Darkviolet (148,0,211)
        /// </summary>
        public static ColorValue Darkviolet { get { return new ColorValue(148, 0, 211); } }

        /// <summary>
        /// X11 Color Blueviolet (138,43,226)
        /// </summary>
        public static ColorValue Blueviolet { get { return new ColorValue(138, 43, 226); } }

        /// <summary>
        /// X11 Color Purple (160,32,240)
        /// </summary>
        public static ColorValue Purple { get { return new ColorValue(160, 32, 240); } }

        /// <summary>
        /// X11 Color Mediumpurple (147,112,219)
        /// </summary>
        public static ColorValue Mediumpurple { get { return new ColorValue(147, 112, 219); } }

        /// <summary>
        /// X11 Color Thistle (216,191,216)
        /// </summary>
        public static ColorValue Thistle { get { return new ColorValue(216, 191, 216); } }

        /// <summary>
        /// X11 Color Snow1 (255,250,250)
        /// </summary>
        public static ColorValue Snow1 { get { return new ColorValue(255, 250, 250); } }

        /// <summary>
        /// X11 Color Snow2 (238,233,233)
        /// </summary>
        public static ColorValue Snow2 { get { return new ColorValue(238, 233, 233); } }

        /// <summary>
        /// X11 Color Snow3 (205,201,201)
        /// </summary>
        public static ColorValue Snow3 { get { return new ColorValue(205, 201, 201); } }

        /// <summary>
        /// X11 Color Snow4 (139,137,137)
        /// </summary>
        public static ColorValue Snow4 { get { return new ColorValue(139, 137, 137); } }

        /// <summary>
        /// X11 Color Seashell1 (255,245,238)
        /// </summary>
        public static ColorValue Seashell1 { get { return new ColorValue(255, 245, 238); } }

        /// <summary>
        /// X11 Color Seashell2 (238,229,222)
        /// </summary>
        public static ColorValue Seashell2 { get { return new ColorValue(238, 229, 222); } }

        /// <summary>
        /// X11 Color Seashell3 (205,197,191)
        /// </summary>
        public static ColorValue Seashell3 { get { return new ColorValue(205, 197, 191); } }

        /// <summary>
        /// X11 Color Seashell4 (139,134,130)
        /// </summary>
        public static ColorValue Seashell4 { get { return new ColorValue(139, 134, 130); } }

        /// <summary>
        /// X11 Color Antiquewhite1 (255,239,219)
        /// </summary>
        public static ColorValue Antiquewhite1 { get { return new ColorValue(255, 239, 219); } }

        /// <summary>
        /// X11 Color Antiquewhite2 (238,223,204)
        /// </summary>
        public static ColorValue Antiquewhite2 { get { return new ColorValue(238, 223, 204); } }

        /// <summary>
        /// X11 Color Antiquewhite3 (205,192,176)
        /// </summary>
        public static ColorValue Antiquewhite3 { get { return new ColorValue(205, 192, 176); } }

        /// <summary>
        /// X11 Color Antiquewhite4 (139,131,120)
        /// </summary>
        public static ColorValue Antiquewhite4 { get { return new ColorValue(139, 131, 120); } }

        /// <summary>
        /// X11 Color Bisque1 (255,228,196)
        /// </summary>
        public static ColorValue Bisque1 { get { return new ColorValue(255, 228, 196); } }

        /// <summary>
        /// X11 Color Bisque2 (238,213,183)
        /// </summary>
        public static ColorValue Bisque2 { get { return new ColorValue(238, 213, 183); } }

        /// <summary>
        /// X11 Color Bisque3 (205,183,158)
        /// </summary>
        public static ColorValue Bisque3 { get { return new ColorValue(205, 183, 158); } }

        /// <summary>
        /// X11 Color Bisque4 (139,125,107)
        /// </summary>
        public static ColorValue Bisque4 { get { return new ColorValue(139, 125, 107); } }

        /// <summary>
        /// X11 Color Peachpuff1 (255,218,185)
        /// </summary>
        public static ColorValue Peachpuff1 { get { return new ColorValue(255, 218, 185); } }

        /// <summary>
        /// X11 Color Peachpuff2 (238,203,173)
        /// </summary>
        public static ColorValue Peachpuff2 { get { return new ColorValue(238, 203, 173); } }

        /// <summary>
        /// X11 Color Peachpuff3 (205,175,149)
        /// </summary>
        public static ColorValue Peachpuff3 { get { return new ColorValue(205, 175, 149); } }

        /// <summary>
        /// X11 Color Peachpuff4 (139,119,101)
        /// </summary>
        public static ColorValue Peachpuff4 { get { return new ColorValue(139, 119, 101); } }

        /// <summary>
        /// X11 Color Navajowhite1 (255,222,173)
        /// </summary>
        public static ColorValue Navajowhite1 { get { return new ColorValue(255, 222, 173); } }

        /// <summary>
        /// X11 Color Navajowhite2 (238,207,161)
        /// </summary>
        public static ColorValue Navajowhite2 { get { return new ColorValue(238, 207, 161); } }

        /// <summary>
        /// X11 Color Navajowhite3 (205,179,139)
        /// </summary>
        public static ColorValue Navajowhite3 { get { return new ColorValue(205, 179, 139); } }

        /// <summary>
        /// X11 Color Navajowhite4 (139,121,94)
        /// </summary>
        public static ColorValue Navajowhite4 { get { return new ColorValue(139, 121, 94); } }

        /// <summary>
        /// X11 Color Lemonchiffon1 (255,250,205)
        /// </summary>
        public static ColorValue Lemonchiffon1 { get { return new ColorValue(255, 250, 205); } }

        /// <summary>
        /// X11 Color Lemonchiffon2 (238,233,191)
        /// </summary>
        public static ColorValue Lemonchiffon2 { get { return new ColorValue(238, 233, 191); } }

        /// <summary>
        /// X11 Color Lemonchiffon3 (205,201,165)
        /// </summary>
        public static ColorValue Lemonchiffon3 { get { return new ColorValue(205, 201, 165); } }

        /// <summary>
        /// X11 Color Lemonchiffon4 (139,137,112)
        /// </summary>
        public static ColorValue Lemonchiffon4 { get { return new ColorValue(139, 137, 112); } }

        /// <summary>
        /// X11 Color Cornsilk1 (255,248,220)
        /// </summary>
        public static ColorValue Cornsilk1 { get { return new ColorValue(255, 248, 220); } }

        /// <summary>
        /// X11 Color Cornsilk2 (238,232,205)
        /// </summary>
        public static ColorValue Cornsilk2 { get { return new ColorValue(238, 232, 205); } }

        /// <summary>
        /// X11 Color Cornsilk3 (205,200,177)
        /// </summary>
        public static ColorValue Cornsilk3 { get { return new ColorValue(205, 200, 177); } }

        /// <summary>
        /// X11 Color Cornsilk4 (139,136,120)
        /// </summary>
        public static ColorValue Cornsilk4 { get { return new ColorValue(139, 136, 120); } }

        /// <summary>
        /// X11 Color Ivory1 (255,255,240)
        /// </summary>
        public static ColorValue Ivory1 { get { return new ColorValue(255, 255, 240); } }

        /// <summary>
        /// X11 Color Ivory2 (238,238,224)
        /// </summary>
        public static ColorValue Ivory2 { get { return new ColorValue(238, 238, 224); } }

        /// <summary>
        /// X11 Color Ivory3 (205,205,193)
        /// </summary>
        public static ColorValue Ivory3 { get { return new ColorValue(205, 205, 193); } }

        /// <summary>
        /// X11 Color Ivory4 (139,139,131)
        /// </summary>
        public static ColorValue Ivory4 { get { return new ColorValue(139, 139, 131); } }

        /// <summary>
        /// X11 Color Honeydew1 (240,255,240)
        /// </summary>
        public static ColorValue Honeydew1 { get { return new ColorValue(240, 255, 240); } }

        /// <summary>
        /// X11 Color Honeydew2 (224,238,224)
        /// </summary>
        public static ColorValue Honeydew2 { get { return new ColorValue(224, 238, 224); } }

        /// <summary>
        /// X11 Color Honeydew3 (193,205,193)
        /// </summary>
        public static ColorValue Honeydew3 { get { return new ColorValue(193, 205, 193); } }

        /// <summary>
        /// X11 Color Honeydew4 (131,139,131)
        /// </summary>
        public static ColorValue Honeydew4 { get { return new ColorValue(131, 139, 131); } }

        /// <summary>
        /// X11 Color Lavenderblush1 (255,240,245)
        /// </summary>
        public static ColorValue Lavenderblush1 { get { return new ColorValue(255, 240, 245); } }

        /// <summary>
        /// X11 Color Lavenderblush2 (238,224,229)
        /// </summary>
        public static ColorValue Lavenderblush2 { get { return new ColorValue(238, 224, 229); } }

        /// <summary>
        /// X11 Color Lavenderblush3 (205,193,197)
        /// </summary>
        public static ColorValue Lavenderblush3 { get { return new ColorValue(205, 193, 197); } }

        /// <summary>
        /// X11 Color Lavenderblush4 (139,131,134)
        /// </summary>
        public static ColorValue Lavenderblush4 { get { return new ColorValue(139, 131, 134); } }

        /// <summary>
        /// X11 Color Mistyrose1 (255,228,225)
        /// </summary>
        public static ColorValue Mistyrose1 { get { return new ColorValue(255, 228, 225); } }

        /// <summary>
        /// X11 Color Mistyrose2 (238,213,210)
        /// </summary>
        public static ColorValue Mistyrose2 { get { return new ColorValue(238, 213, 210); } }

        /// <summary>
        /// X11 Color Mistyrose3 (205,183,181)
        /// </summary>
        public static ColorValue Mistyrose3 { get { return new ColorValue(205, 183, 181); } }

        /// <summary>
        /// X11 Color Mistyrose4 (139,125,123)
        /// </summary>
        public static ColorValue Mistyrose4 { get { return new ColorValue(139, 125, 123); } }

        /// <summary>
        /// X11 Color Azure1 (240,255,255)
        /// </summary>
        public static ColorValue Azure1 { get { return new ColorValue(240, 255, 255); } }

        /// <summary>
        /// X11 Color Azure2 (224,238,238)
        /// </summary>
        public static ColorValue Azure2 { get { return new ColorValue(224, 238, 238); } }

        /// <summary>
        /// X11 Color Azure3 (193,205,205)
        /// </summary>
        public static ColorValue Azure3 { get { return new ColorValue(193, 205, 205); } }

        /// <summary>
        /// X11 Color Azure4 (131,139,139)
        /// </summary>
        public static ColorValue Azure4 { get { return new ColorValue(131, 139, 139); } }

        /// <summary>
        /// X11 Color Slateblue1 (131,111,255)
        /// </summary>
        public static ColorValue Slateblue1 { get { return new ColorValue(131, 111, 255); } }

        /// <summary>
        /// X11 Color Slateblue2 (122,103,238)
        /// </summary>
        public static ColorValue Slateblue2 { get { return new ColorValue(122, 103, 238); } }

        /// <summary>
        /// X11 Color Slateblue3 (105,89,205)
        /// </summary>
        public static ColorValue Slateblue3 { get { return new ColorValue(105, 89, 205); } }

        /// <summary>
        /// X11 Color Slateblue4 (71,60,139)
        /// </summary>
        public static ColorValue Slateblue4 { get { return new ColorValue(71, 60, 139); } }

        /// <summary>
        /// X11 Color Royalblue1 (72,118,255)
        /// </summary>
        public static ColorValue Royalblue1 { get { return new ColorValue(72, 118, 255); } }

        /// <summary>
        /// X11 Color Royalblue2 (67,110,238)
        /// </summary>
        public static ColorValue Royalblue2 { get { return new ColorValue(67, 110, 238); } }

        /// <summary>
        /// X11 Color Royalblue3 (58,95,205)
        /// </summary>
        public static ColorValue Royalblue3 { get { return new ColorValue(58, 95, 205); } }

        /// <summary>
        /// X11 Color Royalblue4 (39,64,139)
        /// </summary>
        public static ColorValue Royalblue4 { get { return new ColorValue(39, 64, 139); } }

        /// <summary>
        /// X11 Color Blue1 (0,0,255)
        /// </summary>
        public static ColorValue Blue1 { get { return new ColorValue(0, 0, 255); } }

        /// <summary>
        /// X11 Color Blue2 (0,0,238)
        /// </summary>
        public static ColorValue Blue2 { get { return new ColorValue(0, 0, 238); } }

        /// <summary>
        /// X11 Color Blue3 (0,0,205)
        /// </summary>
        public static ColorValue Blue3 { get { return new ColorValue(0, 0, 205); } }

        /// <summary>
        /// X11 Color Blue4 (0,0,139)
        /// </summary>
        public static ColorValue Blue4 { get { return new ColorValue(0, 0, 139); } }

        /// <summary>
        /// X11 Color Dodgerblue1 (30,144,255)
        /// </summary>
        public static ColorValue Dodgerblue1 { get { return new ColorValue(30, 144, 255); } }

        /// <summary>
        /// X11 Color Dodgerblue2 (28,134,238)
        /// </summary>
        public static ColorValue Dodgerblue2 { get { return new ColorValue(28, 134, 238); } }

        /// <summary>
        /// X11 Color Dodgerblue3 (24,116,205)
        /// </summary>
        public static ColorValue Dodgerblue3 { get { return new ColorValue(24, 116, 205); } }

        /// <summary>
        /// X11 Color Dodgerblue4 (16,78,139)
        /// </summary>
        public static ColorValue Dodgerblue4 { get { return new ColorValue(16, 78, 139); } }

        /// <summary>
        /// X11 Color Steelblue1 (99,184,255)
        /// </summary>
        public static ColorValue Steelblue1 { get { return new ColorValue(99, 184, 255); } }

        /// <summary>
        /// X11 Color Steelblue2 (92,172,238)
        /// </summary>
        public static ColorValue Steelblue2 { get { return new ColorValue(92, 172, 238); } }

        /// <summary>
        /// X11 Color Steelblue3 (79,148,205)
        /// </summary>
        public static ColorValue Steelblue3 { get { return new ColorValue(79, 148, 205); } }

        /// <summary>
        /// X11 Color Steelblue4 (54,100,139)
        /// </summary>
        public static ColorValue Steelblue4 { get { return new ColorValue(54, 100, 139); } }

        /// <summary>
        /// X11 Color Deepskyblue1 (0,191,255)
        /// </summary>
        public static ColorValue Deepskyblue1 { get { return new ColorValue(0, 191, 255); } }

        /// <summary>
        /// X11 Color Deepskyblue2 (0,178,238)
        /// </summary>
        public static ColorValue Deepskyblue2 { get { return new ColorValue(0, 178, 238); } }

        /// <summary>
        /// X11 Color Deepskyblue3 (0,154,205)
        /// </summary>
        public static ColorValue Deepskyblue3 { get { return new ColorValue(0, 154, 205); } }

        /// <summary>
        /// X11 Color Deepskyblue4 (0,104,139)
        /// </summary>
        public static ColorValue Deepskyblue4 { get { return new ColorValue(0, 104, 139); } }

        /// <summary>
        /// X11 Color Skyblue1 (135,206,255)
        /// </summary>
        public static ColorValue Skyblue1 { get { return new ColorValue(135, 206, 255); } }

        /// <summary>
        /// X11 Color Skyblue2 (126,192,238)
        /// </summary>
        public static ColorValue Skyblue2 { get { return new ColorValue(126, 192, 238); } }

        /// <summary>
        /// X11 Color Skyblue3 (108,166,205)
        /// </summary>
        public static ColorValue Skyblue3 { get { return new ColorValue(108, 166, 205); } }

        /// <summary>
        /// X11 Color Skyblue4 (74,112,139)
        /// </summary>
        public static ColorValue Skyblue4 { get { return new ColorValue(74, 112, 139); } }

        /// <summary>
        /// X11 Color Lightskyblue1 (176,226,255)
        /// </summary>
        public static ColorValue Lightskyblue1 { get { return new ColorValue(176, 226, 255); } }

        /// <summary>
        /// X11 Color Lightskyblue2 (164,211,238)
        /// </summary>
        public static ColorValue Lightskyblue2 { get { return new ColorValue(164, 211, 238); } }

        /// <summary>
        /// X11 Color Lightskyblue3 (141,182,205)
        /// </summary>
        public static ColorValue Lightskyblue3 { get { return new ColorValue(141, 182, 205); } }

        /// <summary>
        /// X11 Color Lightskyblue4 (96,123,139)
        /// </summary>
        public static ColorValue Lightskyblue4 { get { return new ColorValue(96, 123, 139); } }

        /// <summary>
        /// X11 Color Slategray1 (198,226,255)
        /// </summary>
        public static ColorValue Slategray1 { get { return new ColorValue(198, 226, 255); } }

        /// <summary>
        /// X11 Color Slategray2 (185,211,238)
        /// </summary>
        public static ColorValue Slategray2 { get { return new ColorValue(185, 211, 238); } }

        /// <summary>
        /// X11 Color Slategray3 (159,182,205)
        /// </summary>
        public static ColorValue Slategray3 { get { return new ColorValue(159, 182, 205); } }

        /// <summary>
        /// X11 Color Slategray4 (108,123,139)
        /// </summary>
        public static ColorValue Slategray4 { get { return new ColorValue(108, 123, 139); } }

        /// <summary>
        /// X11 Color Lightsteelblue1 (202,225,255)
        /// </summary>
        public static ColorValue Lightsteelblue1 { get { return new ColorValue(202, 225, 255); } }

        /// <summary>
        /// X11 Color Lightsteelblue2 (188,210,238)
        /// </summary>
        public static ColorValue Lightsteelblue2 { get { return new ColorValue(188, 210, 238); } }

        /// <summary>
        /// X11 Color Lightsteelblue3 (162,181,205)
        /// </summary>
        public static ColorValue Lightsteelblue3 { get { return new ColorValue(162, 181, 205); } }

        /// <summary>
        /// X11 Color Lightsteelblue4 (110,123,139)
        /// </summary>
        public static ColorValue Lightsteelblue4 { get { return new ColorValue(110, 123, 139); } }

        /// <summary>
        /// X11 Color Lightblue1 (191,239,255)
        /// </summary>
        public static ColorValue Lightblue1 { get { return new ColorValue(191, 239, 255); } }

        /// <summary>
        /// X11 Color Lightblue2 (178,223,238)
        /// </summary>
        public static ColorValue Lightblue2 { get { return new ColorValue(178, 223, 238); } }

        /// <summary>
        /// X11 Color Lightblue3 (154,192,205)
        /// </summary>
        public static ColorValue Lightblue3 { get { return new ColorValue(154, 192, 205); } }

        /// <summary>
        /// X11 Color Lightblue4 (104,131,139)
        /// </summary>
        public static ColorValue Lightblue4 { get { return new ColorValue(104, 131, 139); } }

        /// <summary>
        /// X11 Color Lightcyan1 (224,255,255)
        /// </summary>
        public static ColorValue Lightcyan1 { get { return new ColorValue(224, 255, 255); } }

        /// <summary>
        /// X11 Color Lightcyan2 (209,238,238)
        /// </summary>
        public static ColorValue Lightcyan2 { get { return new ColorValue(209, 238, 238); } }

        /// <summary>
        /// X11 Color Lightcyan3 (180,205,205)
        /// </summary>
        public static ColorValue Lightcyan3 { get { return new ColorValue(180, 205, 205); } }

        /// <summary>
        /// X11 Color Lightcyan4 (122,139,139)
        /// </summary>
        public static ColorValue Lightcyan4 { get { return new ColorValue(122, 139, 139); } }

        /// <summary>
        /// X11 Color Paleturquoise1 (187,255,255)
        /// </summary>
        public static ColorValue Paleturquoise1 { get { return new ColorValue(187, 255, 255); } }

        /// <summary>
        /// X11 Color Paleturquoise2 (174,238,238)
        /// </summary>
        public static ColorValue Paleturquoise2 { get { return new ColorValue(174, 238, 238); } }

        /// <summary>
        /// X11 Color Paleturquoise3 (150,205,205)
        /// </summary>
        public static ColorValue Paleturquoise3 { get { return new ColorValue(150, 205, 205); } }

        /// <summary>
        /// X11 Color Paleturquoise4 (102,139,139)
        /// </summary>
        public static ColorValue Paleturquoise4 { get { return new ColorValue(102, 139, 139); } }

        /// <summary>
        /// X11 Color Cadetblue1 (152,245,255)
        /// </summary>
        public static ColorValue Cadetblue1 { get { return new ColorValue(152, 245, 255); } }

        /// <summary>
        /// X11 Color Cadetblue2 (142,229,238)
        /// </summary>
        public static ColorValue Cadetblue2 { get { return new ColorValue(142, 229, 238); } }

        /// <summary>
        /// X11 Color Cadetblue3 (122,197,205)
        /// </summary>
        public static ColorValue Cadetblue3 { get { return new ColorValue(122, 197, 205); } }

        /// <summary>
        /// X11 Color Cadetblue4 (83,134,139)
        /// </summary>
        public static ColorValue Cadetblue4 { get { return new ColorValue(83, 134, 139); } }

        /// <summary>
        /// X11 Color Turquoise1 (0,245,255)
        /// </summary>
        public static ColorValue Turquoise1 { get { return new ColorValue(0, 245, 255); } }

        /// <summary>
        /// X11 Color Turquoise2 (0,229,238)
        /// </summary>
        public static ColorValue Turquoise2 { get { return new ColorValue(0, 229, 238); } }

        /// <summary>
        /// X11 Color Turquoise3 (0,197,205)
        /// </summary>
        public static ColorValue Turquoise3 { get { return new ColorValue(0, 197, 205); } }

        /// <summary>
        /// X11 Color Turquoise4 (0,134,139)
        /// </summary>
        public static ColorValue Turquoise4 { get { return new ColorValue(0, 134, 139); } }

        /// <summary>
        /// X11 Color Cyan1 (0,255,255)
        /// </summary>
        public static ColorValue Cyan1 { get { return new ColorValue(0, 255, 255); } }

        /// <summary>
        /// X11 Color Cyan2 (0,238,238)
        /// </summary>
        public static ColorValue Cyan2 { get { return new ColorValue(0, 238, 238); } }

        /// <summary>
        /// X11 Color Cyan3 (0,205,205)
        /// </summary>
        public static ColorValue Cyan3 { get { return new ColorValue(0, 205, 205); } }

        /// <summary>
        /// X11 Color Cyan4 (0,139,139)
        /// </summary>
        public static ColorValue Cyan4 { get { return new ColorValue(0, 139, 139); } }

        /// <summary>
        /// X11 Color Darkslategray1 (151,255,255)
        /// </summary>
        public static ColorValue Darkslategray1 { get { return new ColorValue(151, 255, 255); } }

        /// <summary>
        /// X11 Color Darkslategray2 (141,238,238)
        /// </summary>
        public static ColorValue Darkslategray2 { get { return new ColorValue(141, 238, 238); } }

        /// <summary>
        /// X11 Color Darkslategray3 (121,205,205)
        /// </summary>
        public static ColorValue Darkslategray3 { get { return new ColorValue(121, 205, 205); } }

        /// <summary>
        /// X11 Color Darkslategray4 (82,139,139)
        /// </summary>
        public static ColorValue Darkslategray4 { get { return new ColorValue(82, 139, 139); } }

        /// <summary>
        /// X11 Color Aquamarine1 (127,255,212)
        /// </summary>
        public static ColorValue Aquamarine1 { get { return new ColorValue(127, 255, 212); } }

        /// <summary>
        /// X11 Color Aquamarine2 (118,238,198)
        /// </summary>
        public static ColorValue Aquamarine2 { get { return new ColorValue(118, 238, 198); } }

        /// <summary>
        /// X11 Color Aquamarine3 (102,205,170)
        /// </summary>
        public static ColorValue Aquamarine3 { get { return new ColorValue(102, 205, 170); } }

        /// <summary>
        /// X11 Color Aquamarine4 (69,139,116)
        /// </summary>
        public static ColorValue Aquamarine4 { get { return new ColorValue(69, 139, 116); } }

        /// <summary>
        /// X11 Color Darkseagreen1 (193,255,193)
        /// </summary>
        public static ColorValue Darkseagreen1 { get { return new ColorValue(193, 255, 193); } }

        /// <summary>
        /// X11 Color Darkseagreen2 (180,238,180)
        /// </summary>
        public static ColorValue Darkseagreen2 { get { return new ColorValue(180, 238, 180); } }

        /// <summary>
        /// X11 Color Darkseagreen3 (155,205,155)
        /// </summary>
        public static ColorValue Darkseagreen3 { get { return new ColorValue(155, 205, 155); } }

        /// <summary>
        /// X11 Color Darkseagreen4 (105,139,105)
        /// </summary>
        public static ColorValue Darkseagreen4 { get { return new ColorValue(105, 139, 105); } }

        /// <summary>
        /// X11 Color Seagreen1 (84,255,159)
        /// </summary>
        public static ColorValue Seagreen1 { get { return new ColorValue(84, 255, 159); } }

        /// <summary>
        /// X11 Color Seagreen2 (78,238,148)
        /// </summary>
        public static ColorValue Seagreen2 { get { return new ColorValue(78, 238, 148); } }

        /// <summary>
        /// X11 Color Seagreen3 (67,205,128)
        /// </summary>
        public static ColorValue Seagreen3 { get { return new ColorValue(67, 205, 128); } }

        /// <summary>
        /// X11 Color Seagreen4 (46,139,87)
        /// </summary>
        public static ColorValue Seagreen4 { get { return new ColorValue(46, 139, 87); } }

        /// <summary>
        /// X11 Color Palegreen1 (154,255,154)
        /// </summary>
        public static ColorValue Palegreen1 { get { return new ColorValue(154, 255, 154); } }

        /// <summary>
        /// X11 Color Palegreen2 (144,238,144)
        /// </summary>
        public static ColorValue Palegreen2 { get { return new ColorValue(144, 238, 144); } }

        /// <summary>
        /// X11 Color Palegreen3 (124,205,124)
        /// </summary>
        public static ColorValue Palegreen3 { get { return new ColorValue(124, 205, 124); } }

        /// <summary>
        /// X11 Color Palegreen4 (84,139,84)
        /// </summary>
        public static ColorValue Palegreen4 { get { return new ColorValue(84, 139, 84); } }

        /// <summary>
        /// X11 Color Springgreen1 (0,255,127)
        /// </summary>
        public static ColorValue Springgreen1 { get { return new ColorValue(0, 255, 127); } }

        /// <summary>
        /// X11 Color Springgreen2 (0,238,118)
        /// </summary>
        public static ColorValue Springgreen2 { get { return new ColorValue(0, 238, 118); } }

        /// <summary>
        /// X11 Color Springgreen3 (0,205,102)
        /// </summary>
        public static ColorValue Springgreen3 { get { return new ColorValue(0, 205, 102); } }

        /// <summary>
        /// X11 Color Springgreen4 (0,139,69)
        /// </summary>
        public static ColorValue Springgreen4 { get { return new ColorValue(0, 139, 69); } }

        /// <summary>
        /// X11 Color Green1 (0,255,0)
        /// </summary>
        public static ColorValue Green1 { get { return new ColorValue(0, 255, 0); } }

        /// <summary>
        /// X11 Color Green2 (0,238,0)
        /// </summary>
        public static ColorValue Green2 { get { return new ColorValue(0, 238, 0); } }

        /// <summary>
        /// X11 Color Green3 (0,205,0)
        /// </summary>
        public static ColorValue Green3 { get { return new ColorValue(0, 205, 0); } }

        /// <summary>
        /// X11 Color Green4 (0,139,0)
        /// </summary>
        public static ColorValue Green4 { get { return new ColorValue(0, 139, 0); } }

        /// <summary>
        /// X11 Color Chartreuse1 (127,255,0)
        /// </summary>
        public static ColorValue Chartreuse1 { get { return new ColorValue(127, 255, 0); } }

        /// <summary>
        /// X11 Color Chartreuse2 (118,238,0)
        /// </summary>
        public static ColorValue Chartreuse2 { get { return new ColorValue(118, 238, 0); } }

        /// <summary>
        /// X11 Color Chartreuse3 (102,205,0)
        /// </summary>
        public static ColorValue Chartreuse3 { get { return new ColorValue(102, 205, 0); } }

        /// <summary>
        /// X11 Color Chartreuse4 (69,139,0)
        /// </summary>
        public static ColorValue Chartreuse4 { get { return new ColorValue(69, 139, 0); } }

        /// <summary>
        /// X11 Color Olivedrab1 (192,255,62)
        /// </summary>
        public static ColorValue Olivedrab1 { get { return new ColorValue(192, 255, 62); } }

        /// <summary>
        /// X11 Color Olivedrab2 (179,238,58)
        /// </summary>
        public static ColorValue Olivedrab2 { get { return new ColorValue(179, 238, 58); } }

        /// <summary>
        /// X11 Color Olivedrab3 (154,205,50)
        /// </summary>
        public static ColorValue Olivedrab3 { get { return new ColorValue(154, 205, 50); } }

        /// <summary>
        /// X11 Color Olivedrab4 (105,139,34)
        /// </summary>
        public static ColorValue Olivedrab4 { get { return new ColorValue(105, 139, 34); } }

        /// <summary>
        /// X11 Color Darkolivegreen1 (202,255,112)
        /// </summary>
        public static ColorValue Darkolivegreen1 { get { return new ColorValue(202, 255, 112); } }

        /// <summary>
        /// X11 Color Darkolivegreen2 (188,238,104)
        /// </summary>
        public static ColorValue Darkolivegreen2 { get { return new ColorValue(188, 238, 104); } }

        /// <summary>
        /// X11 Color Darkolivegreen3 (162,205,90)
        /// </summary>
        public static ColorValue Darkolivegreen3 { get { return new ColorValue(162, 205, 90); } }

        /// <summary>
        /// X11 Color Darkolivegreen4 (110,139,61)
        /// </summary>
        public static ColorValue Darkolivegreen4 { get { return new ColorValue(110, 139, 61); } }

        /// <summary>
        /// X11 Color Khaki1 (255,246,143)
        /// </summary>
        public static ColorValue Khaki1 { get { return new ColorValue(255, 246, 143); } }

        /// <summary>
        /// X11 Color Khaki2 (238,230,133)
        /// </summary>
        public static ColorValue Khaki2 { get { return new ColorValue(238, 230, 133); } }

        /// <summary>
        /// X11 Color Khaki3 (205,198,115)
        /// </summary>
        public static ColorValue Khaki3 { get { return new ColorValue(205, 198, 115); } }

        /// <summary>
        /// X11 Color Khaki4 (139,134,78)
        /// </summary>
        public static ColorValue Khaki4 { get { return new ColorValue(139, 134, 78); } }

        /// <summary>
        /// X11 Color Lightgoldenrod1 (255,236,139)
        /// </summary>
        public static ColorValue Lightgoldenrod1 { get { return new ColorValue(255, 236, 139); } }

        /// <summary>
        /// X11 Color Lightgoldenrod2 (238,220,130)
        /// </summary>
        public static ColorValue Lightgoldenrod2 { get { return new ColorValue(238, 220, 130); } }

        /// <summary>
        /// X11 Color Lightgoldenrod3 (205,190,112)
        /// </summary>
        public static ColorValue Lightgoldenrod3 { get { return new ColorValue(205, 190, 112); } }

        /// <summary>
        /// X11 Color Lightgoldenrod4 (139,129,76)
        /// </summary>
        public static ColorValue Lightgoldenrod4 { get { return new ColorValue(139, 129, 76); } }

        /// <summary>
        /// X11 Color Lightyellow1 (255,255,224)
        /// </summary>
        public static ColorValue Lightyellow1 { get { return new ColorValue(255, 255, 224); } }

        /// <summary>
        /// X11 Color Lightyellow2 (238,238,209)
        /// </summary>
        public static ColorValue Lightyellow2 { get { return new ColorValue(238, 238, 209); } }

        /// <summary>
        /// X11 Color Lightyellow3 (205,205,180)
        /// </summary>
        public static ColorValue Lightyellow3 { get { return new ColorValue(205, 205, 180); } }

        /// <summary>
        /// X11 Color Lightyellow4 (139,139,122)
        /// </summary>
        public static ColorValue Lightyellow4 { get { return new ColorValue(139, 139, 122); } }

        /// <summary>
        /// X11 Color Yellow1 (255,255,0)
        /// </summary>
        public static ColorValue Yellow1 { get { return new ColorValue(255, 255, 0); } }

        /// <summary>
        /// X11 Color Yellow2 (238,238,0)
        /// </summary>
        public static ColorValue Yellow2 { get { return new ColorValue(238, 238, 0); } }

        /// <summary>
        /// X11 Color Yellow3 (205,205,0)
        /// </summary>
        public static ColorValue Yellow3 { get { return new ColorValue(205, 205, 0); } }

        /// <summary>
        /// X11 Color Yellow4 (139,139,0)
        /// </summary>
        public static ColorValue Yellow4 { get { return new ColorValue(139, 139, 0); } }

        /// <summary>
        /// X11 Color Gold1 (255,215,0)
        /// </summary>
        public static ColorValue Gold1 { get { return new ColorValue(255, 215, 0); } }

        /// <summary>
        /// X11 Color Gold2 (238,201,0)
        /// </summary>
        public static ColorValue Gold2 { get { return new ColorValue(238, 201, 0); } }

        /// <summary>
        /// X11 Color Gold3 (205,173,0)
        /// </summary>
        public static ColorValue Gold3 { get { return new ColorValue(205, 173, 0); } }

        /// <summary>
        /// X11 Color Gold4 (139,117,0)
        /// </summary>
        public static ColorValue Gold4 { get { return new ColorValue(139, 117, 0); } }

        /// <summary>
        /// X11 Color Goldenrod1 (255,193,37)
        /// </summary>
        public static ColorValue Goldenrod1 { get { return new ColorValue(255, 193, 37); } }

        /// <summary>
        /// X11 Color Goldenrod2 (238,180,34)
        /// </summary>
        public static ColorValue Goldenrod2 { get { return new ColorValue(238, 180, 34); } }

        /// <summary>
        /// X11 Color Goldenrod3 (205,155,29)
        /// </summary>
        public static ColorValue Goldenrod3 { get { return new ColorValue(205, 155, 29); } }

        /// <summary>
        /// X11 Color Goldenrod4 (139,105,20)
        /// </summary>
        public static ColorValue Goldenrod4 { get { return new ColorValue(139, 105, 20); } }

        /// <summary>
        /// X11 Color Darkgoldenrod1 (255,185,15)
        /// </summary>
        public static ColorValue Darkgoldenrod1 { get { return new ColorValue(255, 185, 15); } }

        /// <summary>
        /// X11 Color Darkgoldenrod2 (238,173,14)
        /// </summary>
        public static ColorValue Darkgoldenrod2 { get { return new ColorValue(238, 173, 14); } }

        /// <summary>
        /// X11 Color Darkgoldenrod3 (205,149,12)
        /// </summary>
        public static ColorValue Darkgoldenrod3 { get { return new ColorValue(205, 149, 12); } }

        /// <summary>
        /// X11 Color Darkgoldenrod4 (139,101,8)
        /// </summary>
        public static ColorValue Darkgoldenrod4 { get { return new ColorValue(139, 101, 8); } }

        /// <summary>
        /// X11 Color Rosybrown1 (255,193,193)
        /// </summary>
        public static ColorValue Rosybrown1 { get { return new ColorValue(255, 193, 193); } }

        /// <summary>
        /// X11 Color Rosybrown2 (238,180,180)
        /// </summary>
        public static ColorValue Rosybrown2 { get { return new ColorValue(238, 180, 180); } }

        /// <summary>
        /// X11 Color Rosybrown3 (205,155,155)
        /// </summary>
        public static ColorValue Rosybrown3 { get { return new ColorValue(205, 155, 155); } }

        /// <summary>
        /// X11 Color Rosybrown4 (139,105,105)
        /// </summary>
        public static ColorValue Rosybrown4 { get { return new ColorValue(139, 105, 105); } }

        /// <summary>
        /// X11 Color Indianred1 (255,106,106)
        /// </summary>
        public static ColorValue Indianred1 { get { return new ColorValue(255, 106, 106); } }

        /// <summary>
        /// X11 Color Indianred2 (238,99,99)
        /// </summary>
        public static ColorValue Indianred2 { get { return new ColorValue(238, 99, 99); } }

        /// <summary>
        /// X11 Color Indianred3 (205,85,85)
        /// </summary>
        public static ColorValue Indianred3 { get { return new ColorValue(205, 85, 85); } }

        /// <summary>
        /// X11 Color Indianred4 (139,58,58)
        /// </summary>
        public static ColorValue Indianred4 { get { return new ColorValue(139, 58, 58); } }

        /// <summary>
        /// X11 Color Sienna1 (255,130,71)
        /// </summary>
        public static ColorValue Sienna1 { get { return new ColorValue(255, 130, 71); } }

        /// <summary>
        /// X11 Color Sienna2 (238,121,66)
        /// </summary>
        public static ColorValue Sienna2 { get { return new ColorValue(238, 121, 66); } }

        /// <summary>
        /// X11 Color Sienna3 (205,104,57)
        /// </summary>
        public static ColorValue Sienna3 { get { return new ColorValue(205, 104, 57); } }

        /// <summary>
        /// X11 Color Sienna4 (139,71,38)
        /// </summary>
        public static ColorValue Sienna4 { get { return new ColorValue(139, 71, 38); } }

        /// <summary>
        /// X11 Color Burlywood1 (255,211,155)
        /// </summary>
        public static ColorValue Burlywood1 { get { return new ColorValue(255, 211, 155); } }

        /// <summary>
        /// X11 Color Burlywood2 (238,197,145)
        /// </summary>
        public static ColorValue Burlywood2 { get { return new ColorValue(238, 197, 145); } }

        /// <summary>
        /// X11 Color Burlywood3 (205,170,125)
        /// </summary>
        public static ColorValue Burlywood3 { get { return new ColorValue(205, 170, 125); } }

        /// <summary>
        /// X11 Color Burlywood4 (139,115,85)
        /// </summary>
        public static ColorValue Burlywood4 { get { return new ColorValue(139, 115, 85); } }

        /// <summary>
        /// X11 Color Wheat1 (255,231,186)
        /// </summary>
        public static ColorValue Wheat1 { get { return new ColorValue(255, 231, 186); } }

        /// <summary>
        /// X11 Color Wheat2 (238,216,174)
        /// </summary>
        public static ColorValue Wheat2 { get { return new ColorValue(238, 216, 174); } }

        /// <summary>
        /// X11 Color Wheat3 (205,186,150)
        /// </summary>
        public static ColorValue Wheat3 { get { return new ColorValue(205, 186, 150); } }

        /// <summary>
        /// X11 Color Wheat4 (139,126,102)
        /// </summary>
        public static ColorValue Wheat4 { get { return new ColorValue(139, 126, 102); } }

        /// <summary>
        /// X11 Color Tan1 (255,165,79)
        /// </summary>
        public static ColorValue Tan1 { get { return new ColorValue(255, 165, 79); } }

        /// <summary>
        /// X11 Color Tan2 (238,154,73)
        /// </summary>
        public static ColorValue Tan2 { get { return new ColorValue(238, 154, 73); } }

        /// <summary>
        /// X11 Color Tan3 (205,133,63)
        /// </summary>
        public static ColorValue Tan3 { get { return new ColorValue(205, 133, 63); } }

        /// <summary>
        /// X11 Color Tan4 (139,90,43)
        /// </summary>
        public static ColorValue Tan4 { get { return new ColorValue(139, 90, 43); } }

        /// <summary>
        /// X11 Color Chocolate1 (255,127,36)
        /// </summary>
        public static ColorValue Chocolate1 { get { return new ColorValue(255, 127, 36); } }

        /// <summary>
        /// X11 Color Chocolate2 (238,118,33)
        /// </summary>
        public static ColorValue Chocolate2 { get { return new ColorValue(238, 118, 33); } }

        /// <summary>
        /// X11 Color Chocolate3 (205,102,29)
        /// </summary>
        public static ColorValue Chocolate3 { get { return new ColorValue(205, 102, 29); } }

        /// <summary>
        /// X11 Color Chocolate4 (139,69,19)
        /// </summary>
        public static ColorValue Chocolate4 { get { return new ColorValue(139, 69, 19); } }

        /// <summary>
        /// X11 Color Firebrick1 (255,48,48)
        /// </summary>
        public static ColorValue Firebrick1 { get { return new ColorValue(255, 48, 48); } }

        /// <summary>
        /// X11 Color Firebrick2 (238,44,44)
        /// </summary>
        public static ColorValue Firebrick2 { get { return new ColorValue(238, 44, 44); } }

        /// <summary>
        /// X11 Color Firebrick3 (205,38,38)
        /// </summary>
        public static ColorValue Firebrick3 { get { return new ColorValue(205, 38, 38); } }

        /// <summary>
        /// X11 Color Firebrick4 (139,26,26)
        /// </summary>
        public static ColorValue Firebrick4 { get { return new ColorValue(139, 26, 26); } }

        /// <summary>
        /// X11 Color Brown1 (255,64,64)
        /// </summary>
        public static ColorValue Brown1 { get { return new ColorValue(255, 64, 64); } }

        /// <summary>
        /// X11 Color Brown2 (238,59,59)
        /// </summary>
        public static ColorValue Brown2 { get { return new ColorValue(238, 59, 59); } }

        /// <summary>
        /// X11 Color Brown3 (205,51,51)
        /// </summary>
        public static ColorValue Brown3 { get { return new ColorValue(205, 51, 51); } }

        /// <summary>
        /// X11 Color Brown4 (139,35,35)
        /// </summary>
        public static ColorValue Brown4 { get { return new ColorValue(139, 35, 35); } }

        /// <summary>
        /// X11 Color Salmon1 (255,140,105)
        /// </summary>
        public static ColorValue Salmon1 { get { return new ColorValue(255, 140, 105); } }

        /// <summary>
        /// X11 Color Salmon2 (238,130,98)
        /// </summary>
        public static ColorValue Salmon2 { get { return new ColorValue(238, 130, 98); } }

        /// <summary>
        /// X11 Color Salmon3 (205,112,84)
        /// </summary>
        public static ColorValue Salmon3 { get { return new ColorValue(205, 112, 84); } }

        /// <summary>
        /// X11 Color Salmon4 (139,76,57)
        /// </summary>
        public static ColorValue Salmon4 { get { return new ColorValue(139, 76, 57); } }

        /// <summary>
        /// X11 Color Lightsalmon1 (255,160,122)
        /// </summary>
        public static ColorValue Lightsalmon1 { get { return new ColorValue(255, 160, 122); } }

        /// <summary>
        /// X11 Color Lightsalmon2 (238,149,114)
        /// </summary>
        public static ColorValue Lightsalmon2 { get { return new ColorValue(238, 149, 114); } }

        /// <summary>
        /// X11 Color Lightsalmon3 (205,129,98)
        /// </summary>
        public static ColorValue Lightsalmon3 { get { return new ColorValue(205, 129, 98); } }

        /// <summary>
        /// X11 Color Lightsalmon4 (139,87,66)
        /// </summary>
        public static ColorValue Lightsalmon4 { get { return new ColorValue(139, 87, 66); } }

        /// <summary>
        /// X11 Color Orange1 (255,165,0)
        /// </summary>
        public static ColorValue Orange1 { get { return new ColorValue(255, 165, 0); } }

        /// <summary>
        /// X11 Color Orange2 (238,154,0)
        /// </summary>
        public static ColorValue Orange2 { get { return new ColorValue(238, 154, 0); } }

        /// <summary>
        /// X11 Color Orange3 (205,133,0)
        /// </summary>
        public static ColorValue Orange3 { get { return new ColorValue(205, 133, 0); } }

        /// <summary>
        /// X11 Color Orange4 (139,90,0)
        /// </summary>
        public static ColorValue Orange4 { get { return new ColorValue(139, 90, 0); } }

        /// <summary>
        /// X11 Color Darkorange1 (255,127,0)
        /// </summary>
        public static ColorValue Darkorange1 { get { return new ColorValue(255, 127, 0); } }

        /// <summary>
        /// X11 Color Darkorange2 (238,118,0)
        /// </summary>
        public static ColorValue Darkorange2 { get { return new ColorValue(238, 118, 0); } }

        /// <summary>
        /// X11 Color Darkorange3 (205,102,0)
        /// </summary>
        public static ColorValue Darkorange3 { get { return new ColorValue(205, 102, 0); } }

        /// <summary>
        /// X11 Color Darkorange4 (139,69,0)
        /// </summary>
        public static ColorValue Darkorange4 { get { return new ColorValue(139, 69, 0); } }

        /// <summary>
        /// X11 Color Coral1 (255,114,86)
        /// </summary>
        public static ColorValue Coral1 { get { return new ColorValue(255, 114, 86); } }

        /// <summary>
        /// X11 Color Coral2 (238,106,80)
        /// </summary>
        public static ColorValue Coral2 { get { return new ColorValue(238, 106, 80); } }

        /// <summary>
        /// X11 Color Coral3 (205,91,69)
        /// </summary>
        public static ColorValue Coral3 { get { return new ColorValue(205, 91, 69); } }

        /// <summary>
        /// X11 Color Coral4 (139,62,47)
        /// </summary>
        public static ColorValue Coral4 { get { return new ColorValue(139, 62, 47); } }

        /// <summary>
        /// X11 Color Tomato1 (255,99,71)
        /// </summary>
        public static ColorValue Tomato1 { get { return new ColorValue(255, 99, 71); } }

        /// <summary>
        /// X11 Color Tomato2 (238,92,66)
        /// </summary>
        public static ColorValue Tomato2 { get { return new ColorValue(238, 92, 66); } }

        /// <summary>
        /// X11 Color Tomato3 (205,79,57)
        /// </summary>
        public static ColorValue Tomato3 { get { return new ColorValue(205, 79, 57); } }

        /// <summary>
        /// X11 Color Tomato4 (139,54,38)
        /// </summary>
        public static ColorValue Tomato4 { get { return new ColorValue(139, 54, 38); } }

        /// <summary>
        /// X11 Color Orangered1 (255,69,0)
        /// </summary>
        public static ColorValue Orangered1 { get { return new ColorValue(255, 69, 0); } }

        /// <summary>
        /// X11 Color Orangered2 (238,64,0)
        /// </summary>
        public static ColorValue Orangered2 { get { return new ColorValue(238, 64, 0); } }

        /// <summary>
        /// X11 Color Orangered3 (205,55,0)
        /// </summary>
        public static ColorValue Orangered3 { get { return new ColorValue(205, 55, 0); } }

        /// <summary>
        /// X11 Color Orangered4 (139,37,0)
        /// </summary>
        public static ColorValue Orangered4 { get { return new ColorValue(139, 37, 0); } }

        /// <summary>
        /// X11 Color Red1 (255,0,0)
        /// </summary>
        public static ColorValue Red1 { get { return new ColorValue(255, 0, 0); } }

        /// <summary>
        /// X11 Color Red2 (238,0,0)
        /// </summary>
        public static ColorValue Red2 { get { return new ColorValue(238, 0, 0); } }

        /// <summary>
        /// X11 Color Red3 (205,0,0)
        /// </summary>
        public static ColorValue Red3 { get { return new ColorValue(205, 0, 0); } }

        /// <summary>
        /// X11 Color Red4 (139,0,0)
        /// </summary>
        public static ColorValue Red4 { get { return new ColorValue(139, 0, 0); } }

        /// <summary>
        /// X11 Color Deeppink1 (255,20,147)
        /// </summary>
        public static ColorValue Deeppink1 { get { return new ColorValue(255, 20, 147); } }

        /// <summary>
        /// X11 Color Deeppink2 (238,18,137)
        /// </summary>
        public static ColorValue Deeppink2 { get { return new ColorValue(238, 18, 137); } }

        /// <summary>
        /// X11 Color Deeppink3 (205,16,118)
        /// </summary>
        public static ColorValue Deeppink3 { get { return new ColorValue(205, 16, 118); } }

        /// <summary>
        /// X11 Color Deeppink4 (139,10,80)
        /// </summary>
        public static ColorValue Deeppink4 { get { return new ColorValue(139, 10, 80); } }

        /// <summary>
        /// X11 Color Hotpink1 (255,110,180)
        /// </summary>
        public static ColorValue Hotpink1 { get { return new ColorValue(255, 110, 180); } }

        /// <summary>
        /// X11 Color Hotpink2 (238,106,167)
        /// </summary>
        public static ColorValue Hotpink2 { get { return new ColorValue(238, 106, 167); } }

        /// <summary>
        /// X11 Color Hotpink3 (205,96,144)
        /// </summary>
        public static ColorValue Hotpink3 { get { return new ColorValue(205, 96, 144); } }

        /// <summary>
        /// X11 Color Hotpink4 (139,58,98)
        /// </summary>
        public static ColorValue Hotpink4 { get { return new ColorValue(139, 58, 98); } }

        /// <summary>
        /// X11 Color Pink1 (255,181,197)
        /// </summary>
        public static ColorValue Pink1 { get { return new ColorValue(255, 181, 197); } }

        /// <summary>
        /// X11 Color Pink2 (238,169,184)
        /// </summary>
        public static ColorValue Pink2 { get { return new ColorValue(238, 169, 184); } }

        /// <summary>
        /// X11 Color Pink3 (205,145,158)
        /// </summary>
        public static ColorValue Pink3 { get { return new ColorValue(205, 145, 158); } }

        /// <summary>
        /// X11 Color Pink4 (139,99,108)
        /// </summary>
        public static ColorValue Pink4 { get { return new ColorValue(139, 99, 108); } }

        /// <summary>
        /// X11 Color Lightpink1 (255,174,185)
        /// </summary>
        public static ColorValue Lightpink1 { get { return new ColorValue(255, 174, 185); } }

        /// <summary>
        /// X11 Color Lightpink2 (238,162,173)
        /// </summary>
        public static ColorValue Lightpink2 { get { return new ColorValue(238, 162, 173); } }

        /// <summary>
        /// X11 Color Lightpink3 (205,140,149)
        /// </summary>
        public static ColorValue Lightpink3 { get { return new ColorValue(205, 140, 149); } }

        /// <summary>
        /// X11 Color Lightpink4 (139,95,101)
        /// </summary>
        public static ColorValue Lightpink4 { get { return new ColorValue(139, 95, 101); } }

        /// <summary>
        /// X11 Color Palevioletred1 (255,130,171)
        /// </summary>
        public static ColorValue Palevioletred1 { get { return new ColorValue(255, 130, 171); } }

        /// <summary>
        /// X11 Color Palevioletred2 (238,121,159)
        /// </summary>
        public static ColorValue Palevioletred2 { get { return new ColorValue(238, 121, 159); } }

        /// <summary>
        /// X11 Color Palevioletred3 (205,104,137)
        /// </summary>
        public static ColorValue Palevioletred3 { get { return new ColorValue(205, 104, 137); } }

        /// <summary>
        /// X11 Color Palevioletred4 (139,71,93)
        /// </summary>
        public static ColorValue Palevioletred4 { get { return new ColorValue(139, 71, 93); } }

        /// <summary>
        /// X11 Color Maroon1 (255,52,179)
        /// </summary>
        public static ColorValue Maroon1 { get { return new ColorValue(255, 52, 179); } }

        /// <summary>
        /// X11 Color Maroon2 (238,48,167)
        /// </summary>
        public static ColorValue Maroon2 { get { return new ColorValue(238, 48, 167); } }

        /// <summary>
        /// X11 Color Maroon3 (205,41,144)
        /// </summary>
        public static ColorValue Maroon3 { get { return new ColorValue(205, 41, 144); } }

        /// <summary>
        /// X11 Color Maroon4 (139,28,98)
        /// </summary>
        public static ColorValue Maroon4 { get { return new ColorValue(139, 28, 98); } }

        /// <summary>
        /// X11 Color Violetred1 (255,62,150)
        /// </summary>
        public static ColorValue Violetred1 { get { return new ColorValue(255, 62, 150); } }

        /// <summary>
        /// X11 Color Violetred2 (238,58,140)
        /// </summary>
        public static ColorValue Violetred2 { get { return new ColorValue(238, 58, 140); } }

        /// <summary>
        /// X11 Color Violetred3 (205,50,120)
        /// </summary>
        public static ColorValue Violetred3 { get { return new ColorValue(205, 50, 120); } }

        /// <summary>
        /// X11 Color Violetred4 (139,34,82)
        /// </summary>
        public static ColorValue Violetred4 { get { return new ColorValue(139, 34, 82); } }

        /// <summary>
        /// X11 Color Magenta1 (255,0,255)
        /// </summary>
        public static ColorValue Magenta1 { get { return new ColorValue(255, 0, 255); } }

        /// <summary>
        /// X11 Color Magenta2 (238,0,238)
        /// </summary>
        public static ColorValue Magenta2 { get { return new ColorValue(238, 0, 238); } }

        /// <summary>
        /// X11 Color Magenta3 (205,0,205)
        /// </summary>
        public static ColorValue Magenta3 { get { return new ColorValue(205, 0, 205); } }

        /// <summary>
        /// X11 Color Magenta4 (139,0,139)
        /// </summary>
        public static ColorValue Magenta4 { get { return new ColorValue(139, 0, 139); } }

        /// <summary>
        /// X11 Color Orchid1 (255,131,250)
        /// </summary>
        public static ColorValue Orchid1 { get { return new ColorValue(255, 131, 250); } }

        /// <summary>
        /// X11 Color Orchid2 (238,122,233)
        /// </summary>
        public static ColorValue Orchid2 { get { return new ColorValue(238, 122, 233); } }

        /// <summary>
        /// X11 Color Orchid3 (205,105,201)
        /// </summary>
        public static ColorValue Orchid3 { get { return new ColorValue(205, 105, 201); } }

        /// <summary>
        /// X11 Color Orchid4 (139,71,137)
        /// </summary>
        public static ColorValue Orchid4 { get { return new ColorValue(139, 71, 137); } }

        /// <summary>
        /// X11 Color Plum1 (255,187,255)
        /// </summary>
        public static ColorValue Plum1 { get { return new ColorValue(255, 187, 255); } }

        /// <summary>
        /// X11 Color Plum2 (238,174,238)
        /// </summary>
        public static ColorValue Plum2 { get { return new ColorValue(238, 174, 238); } }

        /// <summary>
        /// X11 Color Plum3 (205,150,205)
        /// </summary>
        public static ColorValue Plum3 { get { return new ColorValue(205, 150, 205); } }

        /// <summary>
        /// X11 Color Plum4 (139,102,139)
        /// </summary>
        public static ColorValue Plum4 { get { return new ColorValue(139, 102, 139); } }

        /// <summary>
        /// X11 Color Mediumorchid1 (224,102,255)
        /// </summary>
        public static ColorValue Mediumorchid1 { get { return new ColorValue(224, 102, 255); } }

        /// <summary>
        /// X11 Color Mediumorchid2 (209,95,238)
        /// </summary>
        public static ColorValue Mediumorchid2 { get { return new ColorValue(209, 95, 238); } }

        /// <summary>
        /// X11 Color Mediumorchid3 (180,82,205)
        /// </summary>
        public static ColorValue Mediumorchid3 { get { return new ColorValue(180, 82, 205); } }

        /// <summary>
        /// X11 Color Mediumorchid4 (122,55,139)
        /// </summary>
        public static ColorValue Mediumorchid4 { get { return new ColorValue(122, 55, 139); } }

        /// <summary>
        /// X11 Color Darkorchid1 (191,62,255)
        /// </summary>
        public static ColorValue Darkorchid1 { get { return new ColorValue(191, 62, 255); } }

        /// <summary>
        /// X11 Color Darkorchid2 (178,58,238)
        /// </summary>
        public static ColorValue Darkorchid2 { get { return new ColorValue(178, 58, 238); } }

        /// <summary>
        /// X11 Color Darkorchid3 (154,50,205)
        /// </summary>
        public static ColorValue Darkorchid3 { get { return new ColorValue(154, 50, 205); } }

        /// <summary>
        /// X11 Color Darkorchid4 (104,34,139)
        /// </summary>
        public static ColorValue Darkorchid4 { get { return new ColorValue(104, 34, 139); } }

        /// <summary>
        /// X11 Color Purple1 (155,48,255)
        /// </summary>
        public static ColorValue Purple1 { get { return new ColorValue(155, 48, 255); } }

        /// <summary>
        /// X11 Color Purple2 (145,44,238)
        /// </summary>
        public static ColorValue Purple2 { get { return new ColorValue(145, 44, 238); } }

        /// <summary>
        /// X11 Color Purple3 (125,38,205)
        /// </summary>
        public static ColorValue Purple3 { get { return new ColorValue(125, 38, 205); } }

        /// <summary>
        /// X11 Color Purple4 (85,26,139)
        /// </summary>
        public static ColorValue Purple4 { get { return new ColorValue(85, 26, 139); } }

        /// <summary>
        /// X11 Color Mediumpurple1 (171,130,255)
        /// </summary>
        public static ColorValue Mediumpurple1 { get { return new ColorValue(171, 130, 255); } }

        /// <summary>
        /// X11 Color Mediumpurple2 (159,121,238)
        /// </summary>
        public static ColorValue Mediumpurple2 { get { return new ColorValue(159, 121, 238); } }

        /// <summary>
        /// X11 Color Mediumpurple3 (137,104,205)
        /// </summary>
        public static ColorValue Mediumpurple3 { get { return new ColorValue(137, 104, 205); } }

        /// <summary>
        /// X11 Color Mediumpurple4 (93,71,139)
        /// </summary>
        public static ColorValue Mediumpurple4 { get { return new ColorValue(93, 71, 139); } }

        /// <summary>
        /// X11 Color Thistle1 (255,225,255)
        /// </summary>
        public static ColorValue Thistle1 { get { return new ColorValue(255, 225, 255); } }

        /// <summary>
        /// X11 Color Thistle2 (238,210,238)
        /// </summary>
        public static ColorValue Thistle2 { get { return new ColorValue(238, 210, 238); } }

        /// <summary>
        /// X11 Color Thistle3 (205,181,205)
        /// </summary>
        public static ColorValue Thistle3 { get { return new ColorValue(205, 181, 205); } }

        /// <summary>
        /// X11 Color Thistle4 (139,123,139)
        /// </summary>
        public static ColorValue Thistle4 { get { return new ColorValue(139, 123, 139); } }

        /// <summary>
        /// X11 Color Gray0 (0,0,0)
        /// </summary>
        public static ColorValue Gray0 { get { return new ColorValue(0, 0, 0); } }

        /// <summary>
        /// X11 Color Grey0 (0,0,0)
        /// </summary>
        public static ColorValue Grey0 { get { return new ColorValue(0, 0, 0); } }

        /// <summary>
        /// X11 Color Gray1 (3,3,3)
        /// </summary>
        public static ColorValue Gray1 { get { return new ColorValue(3, 3, 3); } }

        /// <summary>
        /// X11 Color Grey1 (3,3,3)
        /// </summary>
        public static ColorValue Grey1 { get { return new ColorValue(3, 3, 3); } }

        /// <summary>
        /// X11 Color Gray2 (5,5,5)
        /// </summary>
        public static ColorValue Gray2 { get { return new ColorValue(5, 5, 5); } }

        /// <summary>
        /// X11 Color Grey2 (5,5,5)
        /// </summary>
        public static ColorValue Grey2 { get { return new ColorValue(5, 5, 5); } }

        /// <summary>
        /// X11 Color Gray3 (8,8,8)
        /// </summary>
        public static ColorValue Gray3 { get { return new ColorValue(8, 8, 8); } }

        /// <summary>
        /// X11 Color Grey3 (8,8,8)
        /// </summary>
        public static ColorValue Grey3 { get { return new ColorValue(8, 8, 8); } }

        /// <summary>
        /// X11 Color Gray4 (10,10,10)
        /// </summary>
        public static ColorValue Gray4 { get { return new ColorValue(10, 10, 10); } }

        /// <summary>
        /// X11 Color Grey4 (10,10,10)
        /// </summary>
        public static ColorValue Grey4 { get { return new ColorValue(10, 10, 10); } }

        /// <summary>
        /// X11 Color Gray5 (13,13,13)
        /// </summary>
        public static ColorValue Gray5 { get { return new ColorValue(13, 13, 13); } }

        /// <summary>
        /// X11 Color Grey5 (13,13,13)
        /// </summary>
        public static ColorValue Grey5 { get { return new ColorValue(13, 13, 13); } }

        /// <summary>
        /// X11 Color Gray6 (15,15,15)
        /// </summary>
        public static ColorValue Gray6 { get { return new ColorValue(15, 15, 15); } }

        /// <summary>
        /// X11 Color Grey6 (15,15,15)
        /// </summary>
        public static ColorValue Grey6 { get { return new ColorValue(15, 15, 15); } }

        /// <summary>
        /// X11 Color Gray7 (18,18,18)
        /// </summary>
        public static ColorValue Gray7 { get { return new ColorValue(18, 18, 18); } }

        /// <summary>
        /// X11 Color Grey7 (18,18,18)
        /// </summary>
        public static ColorValue Grey7 { get { return new ColorValue(18, 18, 18); } }

        /// <summary>
        /// X11 Color Gray8 (20,20,20)
        /// </summary>
        public static ColorValue Gray8 { get { return new ColorValue(20, 20, 20); } }

        /// <summary>
        /// X11 Color Grey8 (20,20,20)
        /// </summary>
        public static ColorValue Grey8 { get { return new ColorValue(20, 20, 20); } }

        /// <summary>
        /// X11 Color Gray9 (23,23,23)
        /// </summary>
        public static ColorValue Gray9 { get { return new ColorValue(23, 23, 23); } }

        /// <summary>
        /// X11 Color Grey9 (23,23,23)
        /// </summary>
        public static ColorValue Grey9 { get { return new ColorValue(23, 23, 23); } }

        /// <summary>
        /// X11 Color Gray10 (26,26,26)
        /// </summary>
        public static ColorValue Gray10 { get { return new ColorValue(26, 26, 26); } }

        /// <summary>
        /// X11 Color Grey10 (26,26,26)
        /// </summary>
        public static ColorValue Grey10 { get { return new ColorValue(26, 26, 26); } }

        /// <summary>
        /// X11 Color Gray11 (28,28,28)
        /// </summary>
        public static ColorValue Gray11 { get { return new ColorValue(28, 28, 28); } }

        /// <summary>
        /// X11 Color Grey11 (28,28,28)
        /// </summary>
        public static ColorValue Grey11 { get { return new ColorValue(28, 28, 28); } }

        /// <summary>
        /// X11 Color Gray12 (31,31,31)
        /// </summary>
        public static ColorValue Gray12 { get { return new ColorValue(31, 31, 31); } }

        /// <summary>
        /// X11 Color Grey12 (31,31,31)
        /// </summary>
        public static ColorValue Grey12 { get { return new ColorValue(31, 31, 31); } }

        /// <summary>
        /// X11 Color Gray13 (33,33,33)
        /// </summary>
        public static ColorValue Gray13 { get { return new ColorValue(33, 33, 33); } }

        /// <summary>
        /// X11 Color Grey13 (33,33,33)
        /// </summary>
        public static ColorValue Grey13 { get { return new ColorValue(33, 33, 33); } }

        /// <summary>
        /// X11 Color Gray14 (36,36,36)
        /// </summary>
        public static ColorValue Gray14 { get { return new ColorValue(36, 36, 36); } }

        /// <summary>
        /// X11 Color Grey14 (36,36,36)
        /// </summary>
        public static ColorValue Grey14 { get { return new ColorValue(36, 36, 36); } }

        /// <summary>
        /// X11 Color Gray15 (38,38,38)
        /// </summary>
        public static ColorValue Gray15 { get { return new ColorValue(38, 38, 38); } }

        /// <summary>
        /// X11 Color Grey15 (38,38,38)
        /// </summary>
        public static ColorValue Grey15 { get { return new ColorValue(38, 38, 38); } }

        /// <summary>
        /// X11 Color Gray16 (41,41,41)
        /// </summary>
        public static ColorValue Gray16 { get { return new ColorValue(41, 41, 41); } }

        /// <summary>
        /// X11 Color Grey16 (41,41,41)
        /// </summary>
        public static ColorValue Grey16 { get { return new ColorValue(41, 41, 41); } }

        /// <summary>
        /// X11 Color Gray17 (43,43,43)
        /// </summary>
        public static ColorValue Gray17 { get { return new ColorValue(43, 43, 43); } }

        /// <summary>
        /// X11 Color Grey17 (43,43,43)
        /// </summary>
        public static ColorValue Grey17 { get { return new ColorValue(43, 43, 43); } }

        /// <summary>
        /// X11 Color Gray18 (46,46,46)
        /// </summary>
        public static ColorValue Gray18 { get { return new ColorValue(46, 46, 46); } }

        /// <summary>
        /// X11 Color Grey18 (46,46,46)
        /// </summary>
        public static ColorValue Grey18 { get { return new ColorValue(46, 46, 46); } }

        /// <summary>
        /// X11 Color Gray19 (48,48,48)
        /// </summary>
        public static ColorValue Gray19 { get { return new ColorValue(48, 48, 48); } }

        /// <summary>
        /// X11 Color Grey19 (48,48,48)
        /// </summary>
        public static ColorValue Grey19 { get { return new ColorValue(48, 48, 48); } }

        /// <summary>
        /// X11 Color Gray20 (51,51,51)
        /// </summary>
        public static ColorValue Gray20 { get { return new ColorValue(51, 51, 51); } }

        /// <summary>
        /// X11 Color Grey20 (51,51,51)
        /// </summary>
        public static ColorValue Grey20 { get { return new ColorValue(51, 51, 51); } }

        /// <summary>
        /// X11 Color Gray21 (54,54,54)
        /// </summary>
        public static ColorValue Gray21 { get { return new ColorValue(54, 54, 54); } }

        /// <summary>
        /// X11 Color Grey21 (54,54,54)
        /// </summary>
        public static ColorValue Grey21 { get { return new ColorValue(54, 54, 54); } }

        /// <summary>
        /// X11 Color Gray22 (56,56,56)
        /// </summary>
        public static ColorValue Gray22 { get { return new ColorValue(56, 56, 56); } }

        /// <summary>
        /// X11 Color Grey22 (56,56,56)
        /// </summary>
        public static ColorValue Grey22 { get { return new ColorValue(56, 56, 56); } }

        /// <summary>
        /// X11 Color Gray23 (59,59,59)
        /// </summary>
        public static ColorValue Gray23 { get { return new ColorValue(59, 59, 59); } }

        /// <summary>
        /// X11 Color Grey23 (59,59,59)
        /// </summary>
        public static ColorValue Grey23 { get { return new ColorValue(59, 59, 59); } }

        /// <summary>
        /// X11 Color Gray24 (61,61,61)
        /// </summary>
        public static ColorValue Gray24 { get { return new ColorValue(61, 61, 61); } }

        /// <summary>
        /// X11 Color Grey24 (61,61,61)
        /// </summary>
        public static ColorValue Grey24 { get { return new ColorValue(61, 61, 61); } }

        /// <summary>
        /// X11 Color Gray25 (64,64,64)
        /// </summary>
        public static ColorValue Gray25 { get { return new ColorValue(64, 64, 64); } }

        /// <summary>
        /// X11 Color Grey25 (64,64,64)
        /// </summary>
        public static ColorValue Grey25 { get { return new ColorValue(64, 64, 64); } }

        /// <summary>
        /// X11 Color Gray26 (66,66,66)
        /// </summary>
        public static ColorValue Gray26 { get { return new ColorValue(66, 66, 66); } }

        /// <summary>
        /// X11 Color Grey26 (66,66,66)
        /// </summary>
        public static ColorValue Grey26 { get { return new ColorValue(66, 66, 66); } }

        /// <summary>
        /// X11 Color Gray27 (69,69,69)
        /// </summary>
        public static ColorValue Gray27 { get { return new ColorValue(69, 69, 69); } }

        /// <summary>
        /// X11 Color Grey27 (69,69,69)
        /// </summary>
        public static ColorValue Grey27 { get { return new ColorValue(69, 69, 69); } }

        /// <summary>
        /// X11 Color Gray28 (71,71,71)
        /// </summary>
        public static ColorValue Gray28 { get { return new ColorValue(71, 71, 71); } }

        /// <summary>
        /// X11 Color Grey28 (71,71,71)
        /// </summary>
        public static ColorValue Grey28 { get { return new ColorValue(71, 71, 71); } }

        /// <summary>
        /// X11 Color Gray29 (74,74,74)
        /// </summary>
        public static ColorValue Gray29 { get { return new ColorValue(74, 74, 74); } }

        /// <summary>
        /// X11 Color Grey29 (74,74,74)
        /// </summary>
        public static ColorValue Grey29 { get { return new ColorValue(74, 74, 74); } }

        /// <summary>
        /// X11 Color Gray30 (77,77,77)
        /// </summary>
        public static ColorValue Gray30 { get { return new ColorValue(77, 77, 77); } }

        /// <summary>
        /// X11 Color Grey30 (77,77,77)
        /// </summary>
        public static ColorValue Grey30 { get { return new ColorValue(77, 77, 77); } }

        /// <summary>
        /// X11 Color Gray31 (79,79,79)
        /// </summary>
        public static ColorValue Gray31 { get { return new ColorValue(79, 79, 79); } }

        /// <summary>
        /// X11 Color Grey31 (79,79,79)
        /// </summary>
        public static ColorValue Grey31 { get { return new ColorValue(79, 79, 79); } }

        /// <summary>
        /// X11 Color Gray32 (82,82,82)
        /// </summary>
        public static ColorValue Gray32 { get { return new ColorValue(82, 82, 82); } }

        /// <summary>
        /// X11 Color Grey32 (82,82,82)
        /// </summary>
        public static ColorValue Grey32 { get { return new ColorValue(82, 82, 82); } }

        /// <summary>
        /// X11 Color Gray33 (84,84,84)
        /// </summary>
        public static ColorValue Gray33 { get { return new ColorValue(84, 84, 84); } }

        /// <summary>
        /// X11 Color Grey33 (84,84,84)
        /// </summary>
        public static ColorValue Grey33 { get { return new ColorValue(84, 84, 84); } }

        /// <summary>
        /// X11 Color Gray34 (87,87,87)
        /// </summary>
        public static ColorValue Gray34 { get { return new ColorValue(87, 87, 87); } }

        /// <summary>
        /// X11 Color Grey34 (87,87,87)
        /// </summary>
        public static ColorValue Grey34 { get { return new ColorValue(87, 87, 87); } }

        /// <summary>
        /// X11 Color Gray35 (89,89,89)
        /// </summary>
        public static ColorValue Gray35 { get { return new ColorValue(89, 89, 89); } }

        /// <summary>
        /// X11 Color Grey35 (89,89,89)
        /// </summary>
        public static ColorValue Grey35 { get { return new ColorValue(89, 89, 89); } }

        /// <summary>
        /// X11 Color Gray36 (92,92,92)
        /// </summary>
        public static ColorValue Gray36 { get { return new ColorValue(92, 92, 92); } }

        /// <summary>
        /// X11 Color Grey36 (92,92,92)
        /// </summary>
        public static ColorValue Grey36 { get { return new ColorValue(92, 92, 92); } }

        /// <summary>
        /// X11 Color Gray37 (94,94,94)
        /// </summary>
        public static ColorValue Gray37 { get { return new ColorValue(94, 94, 94); } }

        /// <summary>
        /// X11 Color Grey37 (94,94,94)
        /// </summary>
        public static ColorValue Grey37 { get { return new ColorValue(94, 94, 94); } }

        /// <summary>
        /// X11 Color Gray38 (97,97,97)
        /// </summary>
        public static ColorValue Gray38 { get { return new ColorValue(97, 97, 97); } }

        /// <summary>
        /// X11 Color Grey38 (97,97,97)
        /// </summary>
        public static ColorValue Grey38 { get { return new ColorValue(97, 97, 97); } }

        /// <summary>
        /// X11 Color Gray39 (99,99,99)
        /// </summary>
        public static ColorValue Gray39 { get { return new ColorValue(99, 99, 99); } }

        /// <summary>
        /// X11 Color Grey39 (99,99,99)
        /// </summary>
        public static ColorValue Grey39 { get { return new ColorValue(99, 99, 99); } }

        /// <summary>
        /// X11 Color Gray40 (102,102,102)
        /// </summary>
        public static ColorValue Gray40 { get { return new ColorValue(102, 102, 102); } }

        /// <summary>
        /// X11 Color Grey40 (102,102,102)
        /// </summary>
        public static ColorValue Grey40 { get { return new ColorValue(102, 102, 102); } }

        /// <summary>
        /// X11 Color Gray41 (105,105,105)
        /// </summary>
        public static ColorValue Gray41 { get { return new ColorValue(105, 105, 105); } }

        /// <summary>
        /// X11 Color Grey41 (105,105,105)
        /// </summary>
        public static ColorValue Grey41 { get { return new ColorValue(105, 105, 105); } }

        /// <summary>
        /// X11 Color Gray42 (107,107,107)
        /// </summary>
        public static ColorValue Gray42 { get { return new ColorValue(107, 107, 107); } }

        /// <summary>
        /// X11 Color Grey42 (107,107,107)
        /// </summary>
        public static ColorValue Grey42 { get { return new ColorValue(107, 107, 107); } }

        /// <summary>
        /// X11 Color Gray43 (110,110,110)
        /// </summary>
        public static ColorValue Gray43 { get { return new ColorValue(110, 110, 110); } }

        /// <summary>
        /// X11 Color Grey43 (110,110,110)
        /// </summary>
        public static ColorValue Grey43 { get { return new ColorValue(110, 110, 110); } }

        /// <summary>
        /// X11 Color Gray44 (112,112,112)
        /// </summary>
        public static ColorValue Gray44 { get { return new ColorValue(112, 112, 112); } }

        /// <summary>
        /// X11 Color Grey44 (112,112,112)
        /// </summary>
        public static ColorValue Grey44 { get { return new ColorValue(112, 112, 112); } }

        /// <summary>
        /// X11 Color Gray45 (115,115,115)
        /// </summary>
        public static ColorValue Gray45 { get { return new ColorValue(115, 115, 115); } }

        /// <summary>
        /// X11 Color Grey45 (115,115,115)
        /// </summary>
        public static ColorValue Grey45 { get { return new ColorValue(115, 115, 115); } }

        /// <summary>
        /// X11 Color Gray46 (117,117,117)
        /// </summary>
        public static ColorValue Gray46 { get { return new ColorValue(117, 117, 117); } }

        /// <summary>
        /// X11 Color Grey46 (117,117,117)
        /// </summary>
        public static ColorValue Grey46 { get { return new ColorValue(117, 117, 117); } }

        /// <summary>
        /// X11 Color Gray47 (120,120,120)
        /// </summary>
        public static ColorValue Gray47 { get { return new ColorValue(120, 120, 120); } }

        /// <summary>
        /// X11 Color Grey47 (120,120,120)
        /// </summary>
        public static ColorValue Grey47 { get { return new ColorValue(120, 120, 120); } }

        /// <summary>
        /// X11 Color Gray48 (122,122,122)
        /// </summary>
        public static ColorValue Gray48 { get { return new ColorValue(122, 122, 122); } }

        /// <summary>
        /// X11 Color Grey48 (122,122,122)
        /// </summary>
        public static ColorValue Grey48 { get { return new ColorValue(122, 122, 122); } }

        /// <summary>
        /// X11 Color Gray49 (125,125,125)
        /// </summary>
        public static ColorValue Gray49 { get { return new ColorValue(125, 125, 125); } }

        /// <summary>
        /// X11 Color Grey49 (125,125,125)
        /// </summary>
        public static ColorValue Grey49 { get { return new ColorValue(125, 125, 125); } }

        /// <summary>
        /// X11 Color Gray50 (127,127,127)
        /// </summary>
        public static ColorValue Gray50 { get { return new ColorValue(127, 127, 127); } }

        /// <summary>
        /// X11 Color Grey50 (127,127,127)
        /// </summary>
        public static ColorValue Grey50 { get { return new ColorValue(127, 127, 127); } }

        /// <summary>
        /// X11 Color Gray51 (130,130,130)
        /// </summary>
        public static ColorValue Gray51 { get { return new ColorValue(130, 130, 130); } }

        /// <summary>
        /// X11 Color Grey51 (130,130,130)
        /// </summary>
        public static ColorValue Grey51 { get { return new ColorValue(130, 130, 130); } }

        /// <summary>
        /// X11 Color Gray52 (133,133,133)
        /// </summary>
        public static ColorValue Gray52 { get { return new ColorValue(133, 133, 133); } }

        /// <summary>
        /// X11 Color Grey52 (133,133,133)
        /// </summary>
        public static ColorValue Grey52 { get { return new ColorValue(133, 133, 133); } }

        /// <summary>
        /// X11 Color Gray53 (135,135,135)
        /// </summary>
        public static ColorValue Gray53 { get { return new ColorValue(135, 135, 135); } }

        /// <summary>
        /// X11 Color Grey53 (135,135,135)
        /// </summary>
        public static ColorValue Grey53 { get { return new ColorValue(135, 135, 135); } }

        /// <summary>
        /// X11 Color Gray54 (138,138,138)
        /// </summary>
        public static ColorValue Gray54 { get { return new ColorValue(138, 138, 138); } }

        /// <summary>
        /// X11 Color Grey54 (138,138,138)
        /// </summary>
        public static ColorValue Grey54 { get { return new ColorValue(138, 138, 138); } }

        /// <summary>
        /// X11 Color Gray55 (140,140,140)
        /// </summary>
        public static ColorValue Gray55 { get { return new ColorValue(140, 140, 140); } }

        /// <summary>
        /// X11 Color Grey55 (140,140,140)
        /// </summary>
        public static ColorValue Grey55 { get { return new ColorValue(140, 140, 140); } }

        /// <summary>
        /// X11 Color Gray56 (143,143,143)
        /// </summary>
        public static ColorValue Gray56 { get { return new ColorValue(143, 143, 143); } }

        /// <summary>
        /// X11 Color Grey56 (143,143,143)
        /// </summary>
        public static ColorValue Grey56 { get { return new ColorValue(143, 143, 143); } }

        /// <summary>
        /// X11 Color Gray57 (145,145,145)
        /// </summary>
        public static ColorValue Gray57 { get { return new ColorValue(145, 145, 145); } }

        /// <summary>
        /// X11 Color Grey57 (145,145,145)
        /// </summary>
        public static ColorValue Grey57 { get { return new ColorValue(145, 145, 145); } }

        /// <summary>
        /// X11 Color Gray58 (148,148,148)
        /// </summary>
        public static ColorValue Gray58 { get { return new ColorValue(148, 148, 148); } }

        /// <summary>
        /// X11 Color Grey58 (148,148,148)
        /// </summary>
        public static ColorValue Grey58 { get { return new ColorValue(148, 148, 148); } }

        /// <summary>
        /// X11 Color Gray59 (150,150,150)
        /// </summary>
        public static ColorValue Gray59 { get { return new ColorValue(150, 150, 150); } }

        /// <summary>
        /// X11 Color Grey59 (150,150,150)
        /// </summary>
        public static ColorValue Grey59 { get { return new ColorValue(150, 150, 150); } }

        /// <summary>
        /// X11 Color Gray60 (153,153,153)
        /// </summary>
        public static ColorValue Gray60 { get { return new ColorValue(153, 153, 153); } }

        /// <summary>
        /// X11 Color Grey60 (153,153,153)
        /// </summary>
        public static ColorValue Grey60 { get { return new ColorValue(153, 153, 153); } }

        /// <summary>
        /// X11 Color Gray61 (156,156,156)
        /// </summary>
        public static ColorValue Gray61 { get { return new ColorValue(156, 156, 156); } }

        /// <summary>
        /// X11 Color Grey61 (156,156,156)
        /// </summary>
        public static ColorValue Grey61 { get { return new ColorValue(156, 156, 156); } }

        /// <summary>
        /// X11 Color Gray62 (158,158,158)
        /// </summary>
        public static ColorValue Gray62 { get { return new ColorValue(158, 158, 158); } }

        /// <summary>
        /// X11 Color Grey62 (158,158,158)
        /// </summary>
        public static ColorValue Grey62 { get { return new ColorValue(158, 158, 158); } }

        /// <summary>
        /// X11 Color Gray63 (161,161,161)
        /// </summary>
        public static ColorValue Gray63 { get { return new ColorValue(161, 161, 161); } }

        /// <summary>
        /// X11 Color Grey63 (161,161,161)
        /// </summary>
        public static ColorValue Grey63 { get { return new ColorValue(161, 161, 161); } }

        /// <summary>
        /// X11 Color Gray64 (163,163,163)
        /// </summary>
        public static ColorValue Gray64 { get { return new ColorValue(163, 163, 163); } }

        /// <summary>
        /// X11 Color Grey64 (163,163,163)
        /// </summary>
        public static ColorValue Grey64 { get { return new ColorValue(163, 163, 163); } }

        /// <summary>
        /// X11 Color Gray65 (166,166,166)
        /// </summary>
        public static ColorValue Gray65 { get { return new ColorValue(166, 166, 166); } }

        /// <summary>
        /// X11 Color Grey65 (166,166,166)
        /// </summary>
        public static ColorValue Grey65 { get { return new ColorValue(166, 166, 166); } }

        /// <summary>
        /// X11 Color Gray66 (168,168,168)
        /// </summary>
        public static ColorValue Gray66 { get { return new ColorValue(168, 168, 168); } }

        /// <summary>
        /// X11 Color Grey66 (168,168,168)
        /// </summary>
        public static ColorValue Grey66 { get { return new ColorValue(168, 168, 168); } }

        /// <summary>
        /// X11 Color Gray67 (171,171,171)
        /// </summary>
        public static ColorValue Gray67 { get { return new ColorValue(171, 171, 171); } }

        /// <summary>
        /// X11 Color Grey67 (171,171,171)
        /// </summary>
        public static ColorValue Grey67 { get { return new ColorValue(171, 171, 171); } }

        /// <summary>
        /// X11 Color Gray68 (173,173,173)
        /// </summary>
        public static ColorValue Gray68 { get { return new ColorValue(173, 173, 173); } }

        /// <summary>
        /// X11 Color Grey68 (173,173,173)
        /// </summary>
        public static ColorValue Grey68 { get { return new ColorValue(173, 173, 173); } }

        /// <summary>
        /// X11 Color Gray69 (176,176,176)
        /// </summary>
        public static ColorValue Gray69 { get { return new ColorValue(176, 176, 176); } }

        /// <summary>
        /// X11 Color Grey69 (176,176,176)
        /// </summary>
        public static ColorValue Grey69 { get { return new ColorValue(176, 176, 176); } }

        /// <summary>
        /// X11 Color Gray70 (179,179,179)
        /// </summary>
        public static ColorValue Gray70 { get { return new ColorValue(179, 179, 179); } }

        /// <summary>
        /// X11 Color Grey70 (179,179,179)
        /// </summary>
        public static ColorValue Grey70 { get { return new ColorValue(179, 179, 179); } }

        /// <summary>
        /// X11 Color Gray71 (181,181,181)
        /// </summary>
        public static ColorValue Gray71 { get { return new ColorValue(181, 181, 181); } }

        /// <summary>
        /// X11 Color Grey71 (181,181,181)
        /// </summary>
        public static ColorValue Grey71 { get { return new ColorValue(181, 181, 181); } }

        /// <summary>
        /// X11 Color Gray72 (184,184,184)
        /// </summary>
        public static ColorValue Gray72 { get { return new ColorValue(184, 184, 184); } }

        /// <summary>
        /// X11 Color Grey72 (184,184,184)
        /// </summary>
        public static ColorValue Grey72 { get { return new ColorValue(184, 184, 184); } }

        /// <summary>
        /// X11 Color Gray73 (186,186,186)
        /// </summary>
        public static ColorValue Gray73 { get { return new ColorValue(186, 186, 186); } }

        /// <summary>
        /// X11 Color Grey73 (186,186,186)
        /// </summary>
        public static ColorValue Grey73 { get { return new ColorValue(186, 186, 186); } }

        /// <summary>
        /// X11 Color Gray74 (189,189,189)
        /// </summary>
        public static ColorValue Gray74 { get { return new ColorValue(189, 189, 189); } }

        /// <summary>
        /// X11 Color Grey74 (189,189,189)
        /// </summary>
        public static ColorValue Grey74 { get { return new ColorValue(189, 189, 189); } }

        /// <summary>
        /// X11 Color Gray75 (191,191,191)
        /// </summary>
        public static ColorValue Gray75 { get { return new ColorValue(191, 191, 191); } }

        /// <summary>
        /// X11 Color Grey75 (191,191,191)
        /// </summary>
        public static ColorValue Grey75 { get { return new ColorValue(191, 191, 191); } }

        /// <summary>
        /// X11 Color Gray76 (194,194,194)
        /// </summary>
        public static ColorValue Gray76 { get { return new ColorValue(194, 194, 194); } }

        /// <summary>
        /// X11 Color Grey76 (194,194,194)
        /// </summary>
        public static ColorValue Grey76 { get { return new ColorValue(194, 194, 194); } }

        /// <summary>
        /// X11 Color Gray77 (196,196,196)
        /// </summary>
        public static ColorValue Gray77 { get { return new ColorValue(196, 196, 196); } }

        /// <summary>
        /// X11 Color Grey77 (196,196,196)
        /// </summary>
        public static ColorValue Grey77 { get { return new ColorValue(196, 196, 196); } }

        /// <summary>
        /// X11 Color Gray78 (199,199,199)
        /// </summary>
        public static ColorValue Gray78 { get { return new ColorValue(199, 199, 199); } }

        /// <summary>
        /// X11 Color Grey78 (199,199,199)
        /// </summary>
        public static ColorValue Grey78 { get { return new ColorValue(199, 199, 199); } }

        /// <summary>
        /// X11 Color Gray79 (201,201,201)
        /// </summary>
        public static ColorValue Gray79 { get { return new ColorValue(201, 201, 201); } }

        /// <summary>
        /// X11 Color Grey79 (201,201,201)
        /// </summary>
        public static ColorValue Grey79 { get { return new ColorValue(201, 201, 201); } }

        /// <summary>
        /// X11 Color Gray80 (204,204,204)
        /// </summary>
        public static ColorValue Gray80 { get { return new ColorValue(204, 204, 204); } }

        /// <summary>
        /// X11 Color Grey80 (204,204,204)
        /// </summary>
        public static ColorValue Grey80 { get { return new ColorValue(204, 204, 204); } }

        /// <summary>
        /// X11 Color Gray81 (207,207,207)
        /// </summary>
        public static ColorValue Gray81 { get { return new ColorValue(207, 207, 207); } }

        /// <summary>
        /// X11 Color Grey81 (207,207,207)
        /// </summary>
        public static ColorValue Grey81 { get { return new ColorValue(207, 207, 207); } }

        /// <summary>
        /// X11 Color Gray82 (209,209,209)
        /// </summary>
        public static ColorValue Gray82 { get { return new ColorValue(209, 209, 209); } }

        /// <summary>
        /// X11 Color Grey82 (209,209,209)
        /// </summary>
        public static ColorValue Grey82 { get { return new ColorValue(209, 209, 209); } }

        /// <summary>
        /// X11 Color Gray83 (212,212,212)
        /// </summary>
        public static ColorValue Gray83 { get { return new ColorValue(212, 212, 212); } }

        /// <summary>
        /// X11 Color Grey83 (212,212,212)
        /// </summary>
        public static ColorValue Grey83 { get { return new ColorValue(212, 212, 212); } }

        /// <summary>
        /// X11 Color Gray84 (214,214,214)
        /// </summary>
        public static ColorValue Gray84 { get { return new ColorValue(214, 214, 214); } }

        /// <summary>
        /// X11 Color Grey84 (214,214,214)
        /// </summary>
        public static ColorValue Grey84 { get { return new ColorValue(214, 214, 214); } }

        /// <summary>
        /// X11 Color Gray85 (217,217,217)
        /// </summary>
        public static ColorValue Gray85 { get { return new ColorValue(217, 217, 217); } }

        /// <summary>
        /// X11 Color Grey85 (217,217,217)
        /// </summary>
        public static ColorValue Grey85 { get { return new ColorValue(217, 217, 217); } }

        /// <summary>
        /// X11 Color Gray86 (219,219,219)
        /// </summary>
        public static ColorValue Gray86 { get { return new ColorValue(219, 219, 219); } }

        /// <summary>
        /// X11 Color Grey86 (219,219,219)
        /// </summary>
        public static ColorValue Grey86 { get { return new ColorValue(219, 219, 219); } }

        /// <summary>
        /// X11 Color Gray87 (222,222,222)
        /// </summary>
        public static ColorValue Gray87 { get { return new ColorValue(222, 222, 222); } }

        /// <summary>
        /// X11 Color Grey87 (222,222,222)
        /// </summary>
        public static ColorValue Grey87 { get { return new ColorValue(222, 222, 222); } }

        /// <summary>
        /// X11 Color Gray88 (224,224,224)
        /// </summary>
        public static ColorValue Gray88 { get { return new ColorValue(224, 224, 224); } }

        /// <summary>
        /// X11 Color Grey88 (224,224,224)
        /// </summary>
        public static ColorValue Grey88 { get { return new ColorValue(224, 224, 224); } }

        /// <summary>
        /// X11 Color Gray89 (227,227,227)
        /// </summary>
        public static ColorValue Gray89 { get { return new ColorValue(227, 227, 227); } }

        /// <summary>
        /// X11 Color Grey89 (227,227,227)
        /// </summary>
        public static ColorValue Grey89 { get { return new ColorValue(227, 227, 227); } }

        /// <summary>
        /// X11 Color Gray90 (229,229,229)
        /// </summary>
        public static ColorValue Gray90 { get { return new ColorValue(229, 229, 229); } }

        /// <summary>
        /// X11 Color Grey90 (229,229,229)
        /// </summary>
        public static ColorValue Grey90 { get { return new ColorValue(229, 229, 229); } }

        /// <summary>
        /// X11 Color Gray91 (232,232,232)
        /// </summary>
        public static ColorValue Gray91 { get { return new ColorValue(232, 232, 232); } }

        /// <summary>
        /// X11 Color Grey91 (232,232,232)
        /// </summary>
        public static ColorValue Grey91 { get { return new ColorValue(232, 232, 232); } }

        /// <summary>
        /// X11 Color Gray92 (235,235,235)
        /// </summary>
        public static ColorValue Gray92 { get { return new ColorValue(235, 235, 235); } }

        /// <summary>
        /// X11 Color Grey92 (235,235,235)
        /// </summary>
        public static ColorValue Grey92 { get { return new ColorValue(235, 235, 235); } }

        /// <summary>
        /// X11 Color Gray93 (237,237,237)
        /// </summary>
        public static ColorValue Gray93 { get { return new ColorValue(237, 237, 237); } }

        /// <summary>
        /// X11 Color Grey93 (237,237,237)
        /// </summary>
        public static ColorValue Grey93 { get { return new ColorValue(237, 237, 237); } }

        /// <summary>
        /// X11 Color Gray94 (240,240,240)
        /// </summary>
        public static ColorValue Gray94 { get { return new ColorValue(240, 240, 240); } }

        /// <summary>
        /// X11 Color Grey94 (240,240,240)
        /// </summary>
        public static ColorValue Grey94 { get { return new ColorValue(240, 240, 240); } }

        /// <summary>
        /// X11 Color Gray95 (242,242,242)
        /// </summary>
        public static ColorValue Gray95 { get { return new ColorValue(242, 242, 242); } }

        /// <summary>
        /// X11 Color Grey95 (242,242,242)
        /// </summary>
        public static ColorValue Grey95 { get { return new ColorValue(242, 242, 242); } }

        /// <summary>
        /// X11 Color Gray96 (245,245,245)
        /// </summary>
        public static ColorValue Gray96 { get { return new ColorValue(245, 245, 245); } }

        /// <summary>
        /// X11 Color Grey96 (245,245,245)
        /// </summary>
        public static ColorValue Grey96 { get { return new ColorValue(245, 245, 245); } }

        /// <summary>
        /// X11 Color Gray97 (247,247,247)
        /// </summary>
        public static ColorValue Gray97 { get { return new ColorValue(247, 247, 247); } }

        /// <summary>
        /// X11 Color Grey97 (247,247,247)
        /// </summary>
        public static ColorValue Grey97 { get { return new ColorValue(247, 247, 247); } }

        /// <summary>
        /// X11 Color Gray98 (250,250,250)
        /// </summary>
        public static ColorValue Gray98 { get { return new ColorValue(250, 250, 250); } }

        /// <summary>
        /// X11 Color Grey98 (250,250,250)
        /// </summary>
        public static ColorValue Grey98 { get { return new ColorValue(250, 250, 250); } }

        /// <summary>
        /// X11 Color Gray99 (252,252,252)
        /// </summary>
        public static ColorValue Gray99 { get { return new ColorValue(252, 252, 252); } }

        /// <summary>
        /// X11 Color Grey99 (252,252,252)
        /// </summary>
        public static ColorValue Grey99 { get { return new ColorValue(252, 252, 252); } }

        /// <summary>
        /// X11 Color Gray100 (255,255,255)
        /// </summary>
        public static ColorValue Gray100 { get { return new ColorValue(255, 255, 255); } }

        /// <summary>
        /// X11 Color Grey100 (255,255,255)
        /// </summary>
        public static ColorValue Grey100 { get { return new ColorValue(255, 255, 255); } }

        /// <summary>
        /// X11 Color Darkgrey (169,169,169)
        /// </summary>
        public static ColorValue Darkgrey { get { return new ColorValue(169, 169, 169); } }

        /// <summary>
        /// X11 Color Darkgray (169,169,169)
        /// </summary>
        public static ColorValue Darkgray { get { return new ColorValue(169, 169, 169); } }

        /// <summary>
        /// X11 Color Darkblue (0,0,139)
        /// </summary>
        public static ColorValue Darkblue { get { return new ColorValue(0, 0, 139); } }

        /// <summary>
        /// X11 Color Darkcyan (0,139,139)
        /// </summary>
        public static ColorValue Darkcyan { get { return new ColorValue(0, 139, 139); } }

        /// <summary>
        /// X11 Color Darkmagenta (139,0,139)
        /// </summary>
        public static ColorValue Darkmagenta { get { return new ColorValue(139, 0, 139); } }

        /// <summary>
        /// X11 Color Darkred (139,0,0)
        /// </summary>
        public static ColorValue Darkred { get { return new ColorValue(139, 0, 0); } }

        /// <summary>
        /// X11 Color Lightgreen (144,238,144)
        /// </summary>
        public static ColorValue Lightgreen { get { return new ColorValue(144, 238, 144); } }
    }
}
