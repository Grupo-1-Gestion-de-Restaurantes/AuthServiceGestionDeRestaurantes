using AuthServiceGestionDeRestaurantes.Application.Interfaces;

namespace AuthServiceGestionDeRestaurantes.Api.Models;

public class FormFileAdapter : IFileData
{
    private readonly IFormFile _formFile;

    private byte[]? _data;

    public FormFileAdapter(IFormFile formFile)
    {
        ArgumentNullException.ThrowIfNull(formFile);
        _formFile = formFile;
    }

    public byte[] Data
    {
        get
        {
            if(_data == null)
            {
                using var memoryStream = new MemoryStream();
                _formFile.CopyTo(memoryStream);
                _data = memoryStream.ToArray();
            }
            return _data;
        }
    }

    public string ContentType => _formFile.ContentType;
    public string FileName => _formFile.FileName;
    public long Size => _formFile.Length;
}