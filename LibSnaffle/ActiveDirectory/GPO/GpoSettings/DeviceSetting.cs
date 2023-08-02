namespace LibSnaffle.ActiveDirectory
{
    public class DeviceSetting : GpoSetting
    {
        public string Name { get; set; }
        public string DeviceAction { get; set; }
        public string DeviceClass { get; set; }
        public string DeviceClassGUID { get; set; }
        public string DeviceType { get; set; }
        public string DeviceTypeID { get; set; }
    }
}
