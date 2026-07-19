using System.Threading.Tasks;
using ScamShieldAI.Models;

namespace ScamShieldAI.Services
{
    public interface IScamAnalyzerService
    {
        Task<AnalysisResultViewModel> AnalyzeAsync(string message);
    }
}