namespace M183.Controllers.Dto
{
    public class TwoFactorSetupDto
    {
        public string ManualEntryKey { get; set; } = string.Empty;
        public string QrCodeImageUrl { get; set; } = string.Empty;
    }
}