namespace M183.Controllers.Dto
{
    public class TwoFactorLoginDto
    {
        public int UserId { get; set; }
        public string Code { get; set; } = string.Empty;
    }
}