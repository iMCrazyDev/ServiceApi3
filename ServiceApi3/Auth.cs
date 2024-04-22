using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace ServiceApi3
{
    public class AuthOptions
    {
        public const string ISSUER = "mircoenv.tech";
        public const string AUDIENCE = "user";
        const string KEY = "d3dtneve5max7_1q2w3e4r54tjpotznskpostman888811az";
        public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));
    }
    public class Auth
    {
        public static uint GetUserIdByContext(HttpContext httpContext)
        {
            var user = httpContext.User;
            var claim = user.Claims.First();
            return claim == null ? 0 : uint.Parse(claim.Value);
        }
        public static string Hash(string? password, byte[] salt)
        {
            return Convert.ToBase64String(KeyDerivation.Pbkdf2(
                                    password: password!,
                                    salt: salt,
                                    prf: KeyDerivationPrf.HMACSHA256,
                                    iterationCount: 100000,
                                    numBytesRequested: 256 / 8));
        }
    }
    internal class UserRepository
    {
        public class UserContext : DbContext
        {
            public UserContext()
            {

            }
            public DbSet<User> Users { get; set; }
            public DbSet<Master> Masters { get; set; }
            public DbSet<Slave> Slaves { get; set; }
            public DbSet<Access> Accesses { get; set; }
            public DbSet<SensorData> SensorDatas { get; set; }
            protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
            {
                optionsBuilder.UseNpgsql("Host=45.150.64.196;Database=sensor_data;Username=postgres;Password=asdasd@!edqwAD#@wascx"/* 1234"*/, options => options.UseAdminDatabase("postgres"));
                //optionsBuilder.UseNpgsql("Host=localhost;Database=sensor_data;Username=postgres;Password=1234"/* 1234"*/, options => options.UseAdminDatabase("postgres"));
            }

            public LoginResult Login(LoginData? data)
            {
                try
                {
                    if (string.IsNullOrEmpty(data?.email) || string.IsNullOrEmpty(data?.password))
                    {
                        return new (false, "Invalid auth data");
                    }
                    User user;
                    if ((user = Users.FirstOrDefault(x => x.Email == data!.email)) == null)
                    {
                        return new (false, "Invalid email");
                    }
                    byte[] salt = Convert.FromBase64String(user.Salt!);
                    string hashed = Auth.Hash(data!.password, salt);

                    if (user.Password != hashed)
                    {
                        return new (false, "Invalid password");
                    }

                    var claims = new List<Claim> { new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()) };
                    var jwt = new JwtSecurityToken(
                        issuer: AuthOptions.ISSUER,
                        audience: AuthOptions.AUDIENCE,
                        claims: claims,
                        expires: DateTime.UtcNow.Add(TimeSpan.FromDays(60)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));

                    return new (true, new JwtSecurityTokenHandler().WriteToken(jwt));
                }
                catch { }
                return new (false, "Error");
            }

            public RegisterResult Register(RegisterData? data)
            {
                try
                {
                    if (string.IsNullOrEmpty(data?.email) || string.IsNullOrEmpty(data?.password) || string.IsNullOrEmpty(data?.name))
                    {
                        return new (false, "Invalid register data");
                    }
                    if (Users.FirstOrDefault(x => x.Email == data!.email) != null)
                    {
                        return new (false, "Email is occupied");
                    }
                    byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);
                    string hashed = Auth.Hash(data!.password, salt);

                    Users.Add(new User() { Email = data!.email, Password = hashed, Salt = Convert.ToBase64String(salt), Name= data!.name });
                    SaveChanges();

                    var claims = new List<Claim> { new Claim(JwtRegisteredClaimNames.NameId, Users.FirstOrDefault(x => x.Email == data!.email).Id.ToString()) };
                    var jwt = new JwtSecurityToken(
                        issuer: AuthOptions.ISSUER,
                        audience: AuthOptions.AUDIENCE,
                        claims: claims,
                        expires: DateTime.UtcNow.Add(TimeSpan.FromDays(60)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                    return new (true, new JwtSecurityTokenHandler().WriteToken(jwt));
                }
                catch { }
                return new (false, "Error");
            }

            public User? GetUserById(uint id)
            {
                return Users.FirstOrDefault(x => x.Id == id);
            }

            public string? GetToken(uint master_id, uint user_id)
            {
                try
                {
                    Master master;
                    if ((master = Masters.FirstOrDefault(x => x.Id == master_id && x.User.Id == user_id)) == null) {
                        return "error";
                    }

                    return master.Token;
                }
                catch { }
                return "error";
            }

            public (bool, string) CreateMaster(string? name, User? user)
            {
                try
                {
                    var token = Guid.NewGuid().ToString();
                    Masters.Add(new Master() { Name = name, User = user, Token = token });
                    SaveChanges();

                    return (true, token);
                }
                catch { }
                return (false, "Error");
            }

            public void PushData(Slave slave, string name, int status, double value)
            {
                try
                {
                    SensorDatas.Add(new SensorData() { Slave = slave, Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), Value = value, Name = name, Status = status});
                    SaveChanges();
                }
                catch { }
            }

            public List<SensorData> GetData(long from, long to, uint master_id, uint sensor_id, uint user_id, string name)
            {
                var masters = GetMastersByUser(user_id);
                return SensorDatas.Where(x => x.Name == name && x.Timestamp >= from && to >= x.Timestamp && x.Slave.Master.Id == master_id && x.Slave.Id == sensor_id && (masters.Contains(x.Slave.Master) 
                    || Accesses.FirstOrDefault(y => x.Slave.Id == y.Slave.Id && y.User.Id == user_id) != null)).ToList();
            }
            public List<string> GetDataNames(long from, long to, uint master_id, uint sensor_id, uint user_id)
            {
                var masters = GetMastersByUser(user_id);
                return SensorDatas.Where(x => x.Timestamp >= from && to >= x.Timestamp && x.Slave.Master.Id == master_id && x.Slave.Id == sensor_id && (masters.Contains(x.Slave.Master)
                    || Accesses.FirstOrDefault(y => x.Slave.Id == y.Slave.Id && y.User.Id == user_id) != null)).GroupBy(w => w.Name).Select(z => z.Key).ToList();
            }

            public Master? GetMasterByToken(string? token)
            {
                return Masters.FirstOrDefault(x => x.Token == token);
            }

            public List<Master> GetMastersByUser(uint id)
            {
                var list = Masters.Where(x => x.User.Id == id).ToList();
                list.AddRange(Accesses.Where(x => x.User.Id == id && x.AllSlaves).Select(x => x.Master).ToList());

                return list;
            }

            public void RenameMastersByUser(uint master_id, string new_name)
            {
                var master = Masters.FirstOrDefault(x => x.Id == master_id);
                if (master != null)
                {
                    master.Name = new_name;
                    SaveChanges();
                }
            }

            public List<Slave> GetSlavesByUserAndMaster(uint userId, uint masterId)
            {
                return Slaves.Where(x => x.Master.Id == masterId && x.Master.User.Id == userId).ToList();
            }

            public Slave? GetOrCreateSlaveByMasterAndGuid(uint master_id, string guid, string hardware_name)
            {
                try
                {
                    var slave = Slaves.FirstOrDefault(x => x.Master.Id == master_id && x.Guid == guid);

                    if (slave == null)
                    {
                        slave = new Slave()
                        {
                            Guid = guid,
                            HardwareName = hardware_name,
                            Master = GetMasterById(master_id),
                            Name = null
                        };
                        Slaves.Add(slave);
                        SaveChanges();
                    }

                    return slave;
                }
                catch { }
                return null;
            }

            public Master? GetMasterById(uint master_id)
            {
                return Masters.Include(m => m.User).FirstOrDefault(x => x.Id == master_id);
            }

            public Slave GetSlaveById(uint slave_id)
            {
                return Slaves.Include(x => x.Master).FirstOrDefault(x => x.Id == slave_id);
            }

            public bool RenameSlave(string? newName, Slave slave)
            {
                try
                {
                    slave.Name = newName;
                    SaveChanges();
                    return true;
                }
                catch { }
                return false;
            }
        }
    }

    public class User
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public uint Id { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? Salt { get; set; }
        public string? Name { get; set; }
    }

    [Microsoft.EntityFrameworkCore.Index("Token")]
    public class Master
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public uint Id { get; set; }
        public User? User { get; set; }
        public string? Name { get; set; }
        public string? Token { get; set; }  //guid
    }

    public class Slave
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public uint Id { get; set; }
        public Master? Master { get; set; }
        public string? Guid { get; set; }
        public string? Name { get; set; }
        public string? HardwareName { get; set; }

        public override string ToString()
        {
            return string.IsNullOrEmpty(Name) ? HardwareName : Name;
        }
    }

    public class Access
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public uint Id { get; set; }
        public Master? Master { get; set; }
        public User? User { get; set; }
        public bool AllSlaves { get; set; }
        public Slave? Slave { get; set; }
    }

    [Microsoft.EntityFrameworkCore.Index("Timestamp")]
    public class SensorData
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public uint Id { get; set; }
        public long Timestamp { get; set; }
        public double Value { get; set; }
        public string? Name { get; set; }
        public int Status { get; set; }
        public Slave? Slave { get; set; }
    }
    public record LoginData (string email, string password);
    public record LoginResult (bool result, string details);
    public record RegisterData(string email, string password, string name);
    public record RegisterResult(bool result, string details);
    public record MasterLine(uint id, string name);
    public record SlaveLine(uint id, string name);
    public record SensorLine(uint id, long timestamp, double value, int status, string? name);
    public record GetMasterLine(bool status,string? token);
    public record PushData(string guid, string hardware_name, SlaveData[] values);
    public record SlaveData(string sensor_name, int status, SensorOutput[] sensor_data);
    public record SensorOutput(string sensor_name, double sensor_value);
    [JsonSerializable(typeof(PushData))]
    [JsonSerializable(typeof(SlaveData))]
    [JsonSerializable(typeof(SlaveData[]))]
    [JsonSerializable(typeof(SensorOutput))]
    [JsonSerializable(typeof(SensorOutput[]))]
    [JsonSerializable(typeof(GetMasterLine))]
    [JsonSerializable(typeof(SensorLine))]
    [JsonSerializable(typeof(SensorLine[]))]
    [JsonSerializable(typeof(SlaveLine))]
    [JsonSerializable(typeof(SlaveLine[]))]
    [JsonSerializable(typeof(MasterLine))]
    [JsonSerializable(typeof(MasterLine[]))]
    [JsonSerializable(typeof(LoginData))]
    [JsonSerializable(typeof(LoginResult))]
    [JsonSerializable(typeof(RegisterData))]
    [JsonSerializable(typeof(RegisterResult))]
    internal partial class AppJsonSerializerContext : JsonSerializerContext
    {

    }


}

