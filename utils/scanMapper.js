function riskFields(result) {
  return {
    riskLevel: result.riskLevel,
    scamType: result.scamType,
    attackerIntent: result.attackerIntent,
    confidence: result.confidence,
    indicators: result.indicators || result.detectedIndicators || [],
    recommendedActions: result.recommendedActions || [],
    entities: result.entities || {},
  };
}

module.exports = { riskFields };
