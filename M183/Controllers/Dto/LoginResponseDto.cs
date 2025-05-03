namespace M183.Controllers.Dto
{
    public class LoginResponseDto
    {
        public bool RequiresTwoFactor { get; set; }
        public int? Id { get; set; }
        public string? Username { get; set; }
        public bool? IsAdmin { get; set; }
        public string? Token { get; set; }
        public int? UserId { get; set; } // Only used when RequiresTwoFactor is true
    }
}